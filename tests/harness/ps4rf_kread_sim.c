/* PS4RF W15 -- simulated kernel image for the *daemon* (dev-host rehearsal only).
 *
 * The dev-host build of the daemon links `ps4rf_kread_host.c`, which is honest about having no
 * kernel: `kexec()` fails and there is no kernel base, so a read can never succeed. That is the
 * right stand-in for a build that must fail closed, but it cannot exercise the *success* path of a
 * resident session -- the request, the bounds, the containment, the LSTAR/kbase cross-check, the
 * copy and the event -- against a real daemon.
 *
 * This object is the success-path stand-in for that rehearsal. It is deliberately the same shape as
 * `kread_offline.c` (the case runner), minus its `main` and its case table, so a rehearsal can link
 * the production provider into a daemon:
 *
 *   ps4rf_kread_k_readmsr  -> the synthetic LSTAR (kbase + 0x1c0)
 *   ps4rf_kread_k_read8    -> one byte of the simulated image at (base, rva)
 *   kexec()                -> the simulated syscall-11 dispatch: calls the payload, counts it
 *   get_kernel_base()      -> the synthetic kbase
 *
 * The image is a deterministic pattern, *except* for the windows a run seeds explicitly:
 * `PS4RF_KREAD_SIM_SEED` names a file whose lines are `<rva hex> <bytes hex>` (comments with `#`),
 * so a rehearsal can serve the *real* bytes a released window expects (from the profile's pinned
 * locator) at the compiled rva, while everything else stays the pattern. Without a seed the object
 * behaves exactly like the pattern image -- a rehearsal that forgets its seed reads the pattern and
 * its verification refuses, which is the failure mode we want.
 *
 * `PS4RF_KREAD_SIM_TRACE`, when set, receives one JSON line at exit with the counters a host-side
 * report cannot see: how many bytes were read, from which rva range, how many of them were seeded,
 * how often the dispatch ran. The *event* fields are never produced here -- those come from the
 * production provider, which is the point of this object existing at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "ps4rf_kread.h"
#include "ps4rf_kread_regions.h"

#define SIM_KBASE 0xffffffff998f4000ull
#define SIM_LSTAR (SIM_KBASE + 0x1c0ull)
#define SIM_SIZE 0x2400000u              /* covers every generated region rva + length */

static uint8_t g_sim[SIM_SIZE];
static uint8_t g_seeded[SIM_SIZE];       /* 1 when the byte came from the seed file */
static uint64_t g_lstar = SIM_LSTAR;
static uint64_t g_kbase_sdk = SIM_KBASE;
static unsigned long g_reads;
static unsigned long g_seeded_reads;
static unsigned long g_msr_reads;
static unsigned long g_kexec_calls;
static unsigned long g_dispatch_calls;
static uint32_t g_read_min;
static uint32_t g_read_max;
static int g_ready;
static int g_seed_count;
static int g_kexec_failed;               /* W15R3: PS4RF_KREAD_SIM_MODE=kexec_error */

/* written after every dispatch: the daemon ends its lifetime with _exit(), so atexit() never runs */
static void sim_trace(void);

static uint8_t sim_byte(uint32_t rva) {
  return (uint8_t)((rva * 2654435761u) >> 24);
}

static int hex_nibble(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void seed_one(uint32_t rva, const char *hex) {
  uint32_t i = 0u;
  while (hex[2 * i] && hex[2 * i + 1]) {
    int hi = hex_nibble((unsigned char)hex[2 * i]);
    int lo = hex_nibble((unsigned char)hex[2 * i + 1]);
    if (hi < 0 || lo < 0) break;
    if (rva + i >= SIM_SIZE) break;
    g_sim[rva + i] = (uint8_t)((hi << 4) | lo);
    g_seeded[rva + i] = 1u;
    i++;
  }
  if (i) g_seed_count++;
}

static void load_seed(void) {
  const char *path = getenv("PS4RF_KREAD_SIM_SEED");
  char line[4096];
  FILE *fh;
  if (path == NULL || path[0] == '\0') return;
  fh = fopen(path, "r");
  if (fh == NULL) {
    fprintf(stderr, "ps4rf_kread_sim: cannot open the seed file %s\n", path);
    _exit(4);
  }
  while (fgets(line, (int)sizeof line, fh) != NULL) {
    char *p = line;
    char *hex;
    unsigned long rva;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == '\n' || *p == '\0') continue;
    rva = strtoul(p, &hex, 16);
    if (hex == p) continue;
    while (*hex == ' ' || *hex == '\t') hex++;
    if (*hex == '\0' || *hex == '\n') continue;
    seed_one((uint32_t)rva, hex);
  }
  fclose(fh);
}

/* W15R3: `PS4RF_KREAD_SIM_BOOTTIME="<sec>.<usec>"` seeds the compiled boottime row with a
 * plausible instant so the daemon's own measurement (the kread path, not the host sysctl
 * stand-in) can succeed in a rehearsal. Without it the row keeps its pattern bytes and the module
 * refuses the value -- the fail-closed rehearsal. */
static void seed_boottime(void) {
  const char *v = getenv("PS4RF_KREAD_SIM_BOOTTIME");
  const ps4rf_kread_region *row = &PS4RF_KREAD_REGIONS[PS4RF_KREAD_REGION_IDX_BOOTTIME];
  unsigned long long sec = 0ull;
  unsigned long long usec = 0ull;
  uint8_t bytes[16];
  char hex[2u * 16u + 1u];
  static const char digits[] = "0123456789abcdef";
  size_t i;

  if (v == NULL || v[0] == '\0') return;
  if (sscanf(v, "%llu.%llu", &sec, &usec) != 2) {
    fprintf(stderr, "ps4rf_kread_sim: cannot parse PS4RF_KREAD_SIM_BOOTTIME=%s\n", v);
    _exit(4);
  }
  for (i = 0u; i < 8u; i++) {
    bytes[i] = (uint8_t)((sec >> (8u * i)) & 0xffull);          /* struct timeval.tv_sec  */
    bytes[8u + i] = (uint8_t)((usec >> (8u * i)) & 0xffull);    /* struct timeval.tv_usec */
  }
  for (i = 0u; i < 16u; i++) {
    hex[2u * i] = digits[(bytes[i] >> 4) & 0xfu];
    hex[2u * i + 1u] = digits[bytes[i] & 0xfu];
  }
  hex[32] = '\0';
  seed_one(row->rva, hex);
}

static void sim_init(void) {
  uint32_t i;
  if (g_ready) return;
  for (i = 0u; i < SIM_SIZE; i++) g_sim[i] = sim_byte(i);
  load_seed();
  seed_boottime();
  g_ready = 1;
}

/* ---------------------------------------------------------------- leaf replacements */
uint64_t ps4rf_kread_k_readmsr(uint32_t reg) {
  if (reg != 0xC0000082u) {
    fprintf(stderr, "ps4rf_kread_sim: unexpected MSR 0x%x\n", reg);
    _exit(3);
  }
  g_msr_reads++;
  return g_lstar;
}

uint8_t ps4rf_kread_k_read8(uint64_t base, uint32_t rva) {
  sim_init();
  g_reads++;
  if (base != SIM_KBASE || rva >= SIM_SIZE) {
    fprintf(stderr, "ps4rf_kread_sim: read outside the simulated kernel: 0x%llx + 0x%x\n",
            (unsigned long long)base, rva);
    _exit(3);
  }
  if (g_reads == 1 || rva < g_read_min) g_read_min = rva;
  if (rva > g_read_max) g_read_max = rva;
  if (g_seeded[rva]) g_seeded_reads++;
  return g_sim[rva];
}

uint64_t get_kernel_base(void) { return g_kbase_sdk; }

/* The console dispatch, the same shape the case runner uses (kread_offline.c): the SDK builds
 * { void *syscall_handler; ps4rf_kread_info *info } around the caller's block and calls the payload
 * with a pointer to that wrapper. A payload entered with any other ABI must fail here -- which is
 * exactly what the W12 harness proves in the other direction. */
/* W15R3: `PS4RF_KREAD_SIM_MODE` selects the failure the owner's offline cases need:
 *   (unset) / "ok"  -> the honest dispatch (the default)
 *   "kexec_error"   -> the privileged transition fails; the module reports the run as failed, the
 *                      lifetime stays UNRESOLVED and the agent stays up (the fail-closed case)
 *   "hang"          -> the transition never returns: the session stalls, and the point of the case
 *                      is that the control plane was already established before it does
 */
static void sim_mode_gate(void) {
  const char *mode = getenv("PS4RF_KREAD_SIM_MODE");
  if (mode == NULL || mode[0] == '\0' || strcmp(mode, "ok") == 0) return;
  if (strcmp(mode, "kexec_error") == 0) {
    sim_trace();
    g_kexec_failed = 1;             /* kexec() returns -1 below: no dispatch, no dispatch count */
    return;
  }
  if (strcmp(mode, "hang") == 0) {
    sim_trace();
    for (;;) sleep(3600);
  }
}

static int g_wrapper_field0;

int kexec(void *func, void *user_arg) {
  struct kernel_abi {
    void *syscall_handler;
    ps4rf_kread_info *info;
  } wrapper;
  int (*entry)(void *, struct ps4rf_kread_args *);
  int rc;
  g_kexec_calls++;
  sim_mode_gate();
  if (g_kexec_failed) return -1;
  if (func == NULL) return -1;
  wrapper.syscall_handler = (void *)&g_wrapper_field0;
  wrapper.info = (ps4rf_kread_info *)user_arg;
  entry = (int (*)(void *, struct ps4rf_kread_args *))func;
  g_dispatch_calls++;
  rc = entry(NULL, (struct ps4rf_kread_args *)&wrapper);
  /* the daemon ends its lifetime with _exit(), so atexit() never runs: the counters are written
   * right after every dispatch instead (one bounded read per session -- this is not hot code) */
  sim_trace();
  return rc;
}

/* ---------------------------------------------------------------- agent-side counters */
static void sim_trace(void) {
  const char *path = getenv("PS4RF_KREAD_SIM_TRACE");
  FILE *fh;
  if (path == NULL || path[0] == '\0') return;
  fh = fopen(path, "w");
  if (fh == NULL) return;
  fprintf(fh, "{\"bytes_read\": %lu, \"msr_reads\": %lu, \"kexec_calls\": %lu, "
              "\"dispatch_calls\": %lu, \"read_rva_min\": %u, \"read_rva_max\": %u, "
              "\"seeded_bytes_read\": %lu, \"seeded_windows\": %d, "
              "\"sim_kbase\": \"0x%llx\", \"sim_lstar\": \"0x%llx\"}\n",
          g_reads, g_msr_reads, g_kexec_calls, g_dispatch_calls, (unsigned)g_read_min,
          (unsigned)g_read_max, g_seeded_reads, g_seed_count,
          (unsigned long long)g_kbase_sdk, (unsigned long long)g_lstar);
  fclose(fh);
}

__attribute__((constructor)) static void sim_register(void) {
  sim_init();
  atexit(sim_trace);
}
