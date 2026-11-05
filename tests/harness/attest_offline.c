/* PS4RF W9 offline harness for the read-only attestation callback.
 *
 * It links the *production* callback (native/target/ps4rf_attest.c) and replaces only its two
 * leaf operations -- the MSR read and the single-byte kernel read -- plus the two SDK entry
 * points. Everything in between (the info block layout, the one-shot guard, the LSTAR shape
 * gate, the image identity gate, the byte comparisons, the structural aperture gate, the
 * result validation, the event body) is the code that will run on the console.
 *
 * The scenarios are the fail-closed ones the W9 brief lists: a correct measurement, a
 * corrupted window, an LSTAR of the wrong shape, a caller marker that is missing, and a second
 * invocation that must not happen.
 *
 * Build (see tests/test_attest_offline.py):
 *   gcc -std=c11 -I native/target -I native/src -o attest_offline \
 *       tests/harness/attest_offline.c native/target/ps4rf_attest.c \
 *       native/src/ps4rf_protocol.c native/src/jcs.c \
 *       native/src/sha256.c native/src/chacha20poly1305.c
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ps4rf_attest.h"
#include "ps4rf_libc.h"

#define SIM_KBASE 0xFFFFFFFFA2B30000ull                 /* page aligned, canonical */
#define SIM_LSTAR (SIM_KBASE + 0x1C0ull)
#define SIM_STATIC_BASE 0xFFFFFFFFD00D0000ull
#define SIM_SLIDE (SIM_KBASE - SIM_STATIC_BASE)         /* wraps, as the real one does */

static uint64_t g_lstar = SIM_LSTAR;
static int g_reads = 0;
static int g_kexec_calls = 0;
static int g_corrupt_entry = -1;                        /* index whose window is damaged */
static int g_suppress_magic = 0;

/* ---- leaf replacements (weak symbols in the production file give way to these) ---- */

uint64_t ps4rf_attest_k_readmsr(uint32_t reg) {
  if (reg != 0xC0000082u) {
    fprintf(stderr, "unexpected MSR 0x%x requested\n", reg);
    exit(3);
  }
  return g_lstar;
}

uint8_t ps4rf_attest_k_read8(uint64_t base, uint32_t rva) {
  g_reads++;
  if (base != SIM_KBASE) {
    fprintf(stderr, "read outside the simulated image: base 0x%llx\n",
            (unsigned long long)base);
    exit(3);
  }
  for (uint32_t e = 0; e < PS4RF_ATTEST_ENTRY_COUNT; e++) {
    const ps4rf_attest_entry *row = &PS4RF_ATTEST_TABLE[e];
    if (rva >= row->rva && rva < row->rva + row->len) {
      uint8_t value;
      if (row->kind == PS4RF_ATTEST_KIND_RELOCATED) {
        /* image value plus the slide, like a relocated pointer in the live kernel */
        uint64_t relocated = ps4rf_attest_k_expected_u64(row->expected, SIM_SLIDE,
                                                         PS4RF_ATTEST_KIND_RELOCATED);
        value = (uint8_t)((relocated >> (8u * (rva - row->rva))) & 0xFFu);
      } else {
        value = row->expected[rva - row->rva];
      }
      if ((int)e == g_corrupt_entry && rva == row->rva) value ^= 0xFFu;
      return value;
    }
  }
  return 0u;                                            /* unmapped in the simulation */
}

/* ---- SDK entry points ---- */

uint64_t get_kernel_base(void) {
  return g_lstar - 0x1C0ull;
}

int kexec(void *func, void *user_arg) {
  /* the kernel-side ABI: { void *syscall_handler; void *arg; } with our pointer in the
   * second field, exactly like the SDK's kpayload path */
  struct kernel_args {
    void *syscall_handler;
    ps4rf_attest_info *info;
  } args;
  int (*entry)(void *, struct ps4rf_attest_args *);
  g_kexec_calls++;
  args.syscall_handler = (void *)0xFFFF888800000000ull;
  args.info = (ps4rf_attest_info *)user_arg;
  if (g_suppress_magic) args.info->magic_in = 0u;
  entry = (int (*)(void *, struct ps4rf_attest_args *))func;
  return entry(NULL, (struct ps4rf_attest_args *)&args);
}

/* ---- scenarios ---- */

static ps4rf_attest_info g_info;

/* the status of the (single) STRUCTURAL_ONLY observation, for the harness output */
static uint32_t ps4rf_attest_k_structural_status(const ps4rf_attest_info *info) {
  for (uint32_t e = 0; e < PS4RF_ATTEST_ENTRY_COUNT; e++) {
    if (PS4RF_ATTEST_TABLE[e].policy == PS4RF_ATTEST_POLICY_STRUCTURAL_ONLY) {
      return info->entries[e].status;
    }
  }
  return 99u;
}

/* how many STRICT_FINGERPRINT windows the table declares */
static uint32_t strict_total(void) {
  uint32_t n = 0u;
  for (uint32_t e = 0; e < PS4RF_ATTEST_ENTRY_COUNT; e++) {
    if (PS4RF_ATTEST_TABLE[e].policy == PS4RF_ATTEST_POLICY_STRICT_FINGERPRINT) n++;
  }
  return n;
}

/* The one-shot guard is a property of the production code (one callback per session), so each
 * scenario runs in its own child process: a fresh process is a fresh session. */
static int run_case(const char *name, int corrupt_entry, uint64_t lstar, int suppress_magic,
                    int expect_run, int expect_cb, int expect_strict_matches,
                    int expect_mismatch, int expect_observations,
                    int expect_structural_status, int expect_reads) {
  int status;
  jval *event;
  int failures = 0;
  memset(&g_info, 0, sizeof(g_info));
  g_reads = 0;
  g_kexec_calls = 0;
  g_corrupt_entry = corrupt_entry;
  g_lstar = lstar;
  g_suppress_magic = suppress_magic;

  status = ps4rf_attest_run(&g_info);
  event = ps4rf_attest_event(&g_info, status, "sim-build", "sim-label");

  printf("{ \"case\": \"%s\", \"run_status\": %d, \"cb_status\": %u, \"kexec_calls\": %d, "
         "\"reads\": %d, \"strict_matches\": %u, \"strict_mismatches\": %u, "
         "\"structural_observations\": %u, \"structural_status\": %u, \"magic_out\": %u, "
         "\"kbase_cross\": \"%s\", \"read_count\": %u, \"entry_count\": %u, "
         "\"event_status\": ", name, status, g_info.cb_status, g_kexec_calls, g_reads,
         g_info.strict_matches, g_info.strict_mismatches, g_info.structural_observations,
         ps4rf_attest_k_structural_status(&g_info), g_info.magic_out,
         g_info.kbase_lstar == g_info.kbase_sdk ? "MATCH" : "MISMATCH", g_info.read_count,
         g_info.entry_count);
  if (event == NULL) {
    printf("null }\n");
  } else {
    const char *ev_status = jval_string(jval_get(event, "status"), NULL);
    printf("\"%s\" }\n", ev_status != NULL ? ev_status : "?");
    jval_free(event);
  }

  if (status != expect_run) {
    printf("# %s: run_status %d != expected %d\n", name, status, expect_run);
    failures++;
  }
  if ((int)g_info.cb_status != expect_cb) {
    printf("# %s: cb_status %u != expected %d\n", name, g_info.cb_status, expect_cb);
    failures++;
  }
  if ((int)g_info.strict_mismatches != expect_mismatch) {
    printf("# %s: strict_mismatches %u != expected %d\n", name, g_info.strict_mismatches,
           expect_mismatch);
    failures++;
  }
  if ((int)g_info.strict_matches != expect_strict_matches) {
    printf("# %s: strict_matches %u != expected %d\n", name, g_info.strict_matches,
           expect_strict_matches);
    failures++;
  }
  if ((int)g_info.structural_observations != expect_observations) {
    printf("# %s: structural_observations %u != expected %d\n", name,
           g_info.structural_observations, expect_observations);
    failures++;
  }
  if (expect_structural_status != 99 &&
      (int)ps4rf_attest_k_structural_status(&g_info) != expect_structural_status) {
    printf("# %s: structural status %u != expected %d\n", name,
           ps4rf_attest_k_structural_status(&g_info), expect_structural_status);
    failures++;
  }
  /* a STRUCTURAL_ONLY window must never enter the strict score: the strict figures can never
   * exceed the strict window count, and once every window has been measured they must exhaust
   * it exactly. An early stop (bad image identity, bad LSTAR, missing marker) legitimately
   * leaves part of the score empty. */
  uint32_t strict_scored = (uint32_t)g_info.strict_matches + (uint32_t)g_info.strict_mismatches;
  if (strict_scored > strict_total()) {
    printf("# %s: strict score %u exceeds the strict window count %u\n", name, strict_scored,
           strict_total());
    failures++;
  }
  if (g_reads >= 104 && strict_scored != strict_total()) {
    printf("# %s: full read budget but strict score %u != %u\n", name, strict_scored,
           strict_total());
    failures++;
  }
  if (g_kexec_calls != 1) {
    printf("# %s: kexec was called %d times (must be exactly once)\n", name, g_kexec_calls);
    failures++;
  }
  if (g_reads != expect_reads) {
    printf("# %s: %d byte reads, expected exactly %d (bounded measurement set)\n", name,
           g_reads, expect_reads);
    failures++;
  }
  return failures;
}

struct scenario {
  const char *name;
  int corrupt_entry;
  uint64_t lstar;
  int suppress_magic;
  int expect_run;
  int expect_cb;
  int expect_strict_matches;       /* STRICT_FINGERPRINT windows that must match */
  int expect_mismatch;             /* STRICT_FINGERPRINT windows that must not match */
  int expect_observations;         /* STRUCTURAL_ONLY windows measured */
  int expect_structural_status;    /* 99 = do not care */
  int expect_reads;                /* bounded: exactly this many byte reads, no more */
  int one_shot_probe;              /* also verify that a second call is refused */
};

static const struct scenario SCENARIOS[] = {
    /* a correct measurement: 7/7 strict windows match, 1 structural observation, cross-check
     * agrees, 104 bytes read (16+16+16+24+8+8+8+8). Deliberately NOT reported as "8/8". */
    {"clean_measurement", -1, SIM_LSTAR, 0, PS4RF_ATTEST_RUN_OK, PS4RF_ATTEST_CB_OK,
     7, 0, 1, PS4RF_ATTEST_ENTRY_STRUCT_OK, 104, 1},
    /* a STRICT_FINGERPRINT window changed: mismatch and therefore a stop */
    {"strict_window_changed_amd_iommu", 1, SIM_LSTAR, 0, PS4RF_ATTEST_RUN_CALLBACK,
     PS4RF_ATTEST_CB_OK, 6, 1, 1, PS4RF_ATTEST_ENTRY_STRUCT_OK, 104, 0},
    /* the image identity gates everything: a bad first window stops the measurement after
     * the first 16 byte window */
    {"corrupted_image_identity", 0, SIM_LSTAR, 0, PS4RF_ATTEST_RUN_CALLBACK,
     PS4RF_ATTEST_CB_IMAGE, 0, 1, 0, 99, 16, 0},
    /* STRUCTURAL_ONLY changed (here even out of range): the attestation stays valid and the
     * observation is documented instead of becoming a failure */
    {"structural_only_changed_aperture", 7, SIM_LSTAR, 0, PS4RF_ATTEST_RUN_OK,
     PS4RF_ATTEST_CB_OK, 7, 0, 1, PS4RF_ATTEST_ENTRY_STRUCT_BAD, 104, 0},
    /* LSTAR of the wrong shape: not a single byte is read afterwards */
    {"lstar_wrong_shape", -1, SIM_KBASE + 0x1000ull, 0, PS4RF_ATTEST_RUN_CALLBACK,
     PS4RF_ATTEST_CB_LSTAR_SHAPE, 0, 0, 0, 99, 0, 0},
    /* missing caller marker: the callback refuses before touching anything */
    {"caller_marker_missing", -1, SIM_LSTAR, 1, PS4RF_ATTEST_RUN_CALLBACK,
     PS4RF_ATTEST_CB_MAGIC, 0, 0, 0, 99, 0, 0},
};

int main(void) {
  int failures = 0;
  size_t count = sizeof(SCENARIOS) / sizeof(SCENARIOS[0]);

  for (size_t i = 0; i < count; i++) {
    const struct scenario *s = &SCENARIOS[i];
    pid_t child = fork();
    int status = 0;
    if (child == 0) {
      int local = run_case(s->name, s->corrupt_entry, s->lstar, s->suppress_magic,
                           s->expect_run, s->expect_cb, s->expect_strict_matches,
                           s->expect_mismatch, s->expect_observations,
                           s->expect_structural_status, s->expect_reads);
      if (local == 0 && s->one_shot_probe) {
        ps4rf_attest_info second;
        memset(&second, 0, sizeof(second));
        g_kexec_calls = 0;
        g_reads = 0;
        if (ps4rf_attest_run(&second) != PS4RF_ATTEST_RUN_ALREADY) {
          printf("# one_shot: the second invocation was not refused\n");
          local++;
        }
        if (g_kexec_calls != 0 || g_reads != 0) {
          printf("# one_shot: a refused call still touched the kernel (%d kexec, %d reads)\n",
                 g_kexec_calls, g_reads);
          local++;
        }
      }
      exit(local == 0 ? 0 : 1);
    }
    if (child < 0) {
      printf("# could not fork scenario %s\n", s->name);
      failures++;
      continue;
    }
    waitpid(child, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) failures++;
  }

  printf("{ \"scenarios\": %zu, \"scenarios_failed\": %d }\n", count, failures);
  return failures == 0 ? 0 : 1;
}
