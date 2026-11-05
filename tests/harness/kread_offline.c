/* PS4RF W12 offline harness for the bounded kernel.read provider.
 *
 * It links the *production* callback path (native/target/ps4rf_kread.c) and replaces only its
 * leaf operations and the two SDK entry points:
 *
 *   ps4rf_kread_k_readmsr -> returns the synthetic LSTAR (NEVER executes a real rdmsr)
 *   ps4rf_kread_k_read8   -> serves the synthetic kernel image, counts every byte read
 *   kexec()               -> simulates the console syscall-11 dispatch and calls the payload
 *   get_kernel_base()     -> returns the synthetic kernel base
 *
 * Everything in between -- the argument block check, the caller marker, the full request
 * validation (region index, length, 32 bit checked add, region containment), the LSTAR shape
 * gate, the kbase cross check, the canonical resolved runtime VA, the one-shot guard and the
 * bounded copy -- is the production code that runs on the console.
 *
 * Synthetic kernel (deterministic, fixed):
 *   kbase   0xffffffff998f4000  (the value the W9 live run observed)
 *   LSTAR   kbase + 0x1c0
 *   image   a deterministic byte pattern covering every region of the generated table; byte at
 *           rva is (uint8_t)((rva * 2654435761u) >> 24)
 *   get_kernel_base() returns the synthetic kbase (case G returns a different one)
 *
 * Dispatch ABI: the kernel-side shape the console actually uses (proven live by the W9
 * attestation run and carried by W11.2): the kernel builds { void *syscall_handler; payload }
 * and passes a pointer to that wrapper to the callback; the caller's payload pointer sits in
 * the SECOND field (offset 8). The harness reproduces exactly that dispatch; it does not
 * invent a friendlier one, and no host-ABI assumption is mixed in.
 *
 * Kernel-write detection on the host:
 *   - the wrapper's first field points at a harness-owned block. On the console that field is
 *     kernel memory (the syscall handler). A callback that read field 0 as its argument block
 *     would write a status word *there*: the harness snapshots the block and refuses the case
 *     if a single byte changed (that is the console "kernel write").
 *   - case J makes this active: field 0 points at a decoy block that carries a *valid* caller
 *     marker, so a wrong-ABI callback would proceed and write into it; the case proves the
 *     decoy is byte-identical after the dispatch.
 *   - a store through any kbase-derived address cannot be mapped on the host; it faults and
 *     kills the case child (reported as a signal), never silently succeeding.
 *   - the simulated kernel image is sha256-hashed before and after every case
 *     (kernel_mem_writes must stay 0).
 *
 * Cases (each in its own child process: a fresh process is a fresh one-shot session):
 *   A   valid read of the first table region         -> RUN_OK, exact bytes, measured sha256
 *   B   length 0 (run entry)                          -> RUN_REQUEST_INVALID, zero kernel access
 *   C   length PS4RF_KREAD_MAX_LEN + 1 (run entry)    -> RUN_REQUEST_INVALID, zero kernel access
 *   D   offset 0xffffffff + 16 (u32 wraparound)       -> RUN_REQUEST_INVALID, zero kernel access
 *   E   offset == region end + 1 (run entry)          -> RUN_REQUEST_INVALID, zero kernel access
 *   E2  offset == region end - 1, length 2 (one over) -> RUN_REQUEST_INVALID, zero kernel access
 *   F   LSTAR shape wrong                             -> CB_LSTAR_SHAPE, zero bytes read
 *   G   kbase cross-check mismatch                    -> CB_KBASE_MISMATCH, zero bytes read
 *   H   three calls after a success (host retry)      -> RUN_ALREADY, zero deltas, one callback
 *   I   retry after a refused request                 -> RUN_ALREADY, zero deltas
 *   J   dispatch wrapper field 0 = decoy with valid marker -> decoy byte-identical, zero writes
 *   B2  callback, zero length (direct dispatch)       -> CB_LENGTH, no rdmsr, zero bytes read
 *   D2  callback, u32 wraparound (direct dispatch)    -> CB_OVERFLOW, no rdmsr, zero bytes read
 *   E3  callback, cross-region (direct dispatch)      -> CB_CONTAINMENT, no rdmsr, zero reads
 *   K   write scan after a success                    -> kernel_mem_writes=0, cage intact
 *   L   write scan after a refusal                    -> kernel_mem_writes=0, cage intact
 *   M   read ending exactly at the region end         -> RUN_OK (the containment boundary)
 *
 * Output: one JSON object per case, then one summary line;
 *   {"suite":"w12_kread_offline","cases":[...],"cases_failed":N}
 * Exit code 0 only when every case passed. Build and run: tests/test_kread_offline.py.
 * Offline only: no network, no console, no rdmsr.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ps4rf_kread.h"
#include "ps4rf_kread_regions.h"
#include "sha256.h"

#define SIM_KBASE 0xffffffff998f4000ull
#define SIM_LSTAR (SIM_KBASE + 0x1c0ull)
#define SIM_SIZE 0x2A00000u          /* covers every generated region rva + length */
#define CANARY_MAGIC 0xDEADBEEFu
#define OBS_MAX 1024
#define LINE_MAX 1400
#define HEX_MAX (2u * PS4RF_KREAD_MAX_LEN + 1u)

/* ------------------------------------------------------------------ synthetic state */

static uint8_t g_sim[SIM_SIZE];
static uint64_t g_lstar = SIM_LSTAR;
static uint64_t g_kbase_sdk = SIM_KBASE;
static int g_reads;              /* ps4rf_kread_k_read8 calls (byte reads)                */
static int g_msr_reads;          /* ps4rf_kread_k_readmsr calls (synthetic LSTAR reads)   */
static int g_kexec_calls;        /* kexec() calls                                         */
static int g_dispatch_calls;     /* callback entries (through the simulated dispatch)     */
static uint32_t g_read_min;      /* smallest rva served                                   */
static uint32_t g_read_max;      /* largest rva served                                    */
static char g_bytes_hex[HEX_MAX];
static char g_sha_hex[65];

/* The synthetic kernel's syscall_handler target: never a real kernel address on the host.
 * A console-correct payload never touches it. */
static ps4rf_kread_info g_wrapper_field_target;
/* Case J: a decoy that *does* carry a valid caller marker, so a wrong-ABI callback would
 * proceed and write into it -- the write the harness must catch. */
static ps4rf_kread_info g_wrapper_decoy;
static ps4rf_kread_info g_decoy_snapshot;
static ps4rf_kread_info g_canary_snapshot;

static uint8_t sim_byte(uint32_t rva) {
  return (uint8_t)((rva * 2654435761u) >> 24);
}

static void sim_fill(void) {
  for (uint32_t i = 0u; i < SIM_SIZE; i++) g_sim[i] = sim_byte(i);
}

static void sim_digest(uint8_t out[32]) {
  ps4rf_sha256(g_sim, (size_t)SIM_SIZE, out);
}

static void hex(const uint8_t *data, uint32_t len, char *out, size_t cap) {
  static const char digits[] = "0123456789abcdef";
  size_t o = 0u;
  for (uint32_t i = 0u; i < len && o + 2u < cap; i++) {
    out[o++] = digits[(data[i] >> 4) & 0xfu];
    out[o++] = digits[data[i] & 0xfu];
  }
  out[o] = '\0';
}

/* ------------------------------------------------------------------ leaf replacements */

uint64_t ps4rf_kread_k_readmsr(uint32_t reg) {
  g_msr_reads++;
  if (reg != 0xC0000082u) {
    fprintf(stderr, "unexpected MSR 0x%x requested\n", reg);
    _exit(3);
  }
  return g_lstar;
}

uint8_t ps4rf_kread_k_read8(uint64_t base, uint32_t rva) {
  g_reads++;
  if (base != SIM_KBASE || rva >= SIM_SIZE) {
    fprintf(stderr, "read outside the simulated kernel: 0x%llx + 0x%x\n",
            (unsigned long long)base, rva);
    _exit(3);
  }
  if (g_reads == 1 || rva < g_read_min) g_read_min = rva;
  if (rva > g_read_max) g_read_max = rva;
  return g_sim[rva];
}

/* ------------------------------------------------------------------ SDK entry points */

uint64_t get_kernel_base(void) { return g_kbase_sdk; }

static int dispatch_to(void *func, void *field0, ps4rf_kread_info *info) {
  /* the console dispatch: { void *syscall_handler; payload } with the caller's pointer in the
   * second field; the payload is called with a pointer to this wrapper, exactly like the SDK's
   * kpayload path (see ps4rf_attest.h, the W9 live run and W11.2) */
#ifdef PS4RF_KREAD_HARNESS_MUTANT_HOST_ABI
  /* COUNTER-PROOF BUILD (never used by the real suite): a wrapper that puts the payload block
   * in the FIRST field, i.e. the host-ABI assumption the console does not satisfy. The
   * production callback must refuse it and must not write a single byte anywhere. The suite
   * compiles this variant to prove the harness actually discriminates the dispatch ABI. */
  struct kernel_abi {
    ps4rf_kread_info *info;
  } wrapper;
  int (*entry)(void *, struct ps4rf_kread_args *);
  (void)field0;
  wrapper.info = info;
  entry = (int (*)(void *, struct ps4rf_kread_args *))func;
  g_dispatch_calls++;
  return entry(NULL, (struct ps4rf_kread_args *)&wrapper);
#else
  struct kernel_abi {
    void *syscall_handler;
    ps4rf_kread_info *info;
  } wrapper;
  int (*entry)(void *, struct ps4rf_kread_args *);
  wrapper.syscall_handler = field0;
  wrapper.info = info;
  entry = (int (*)(void *, struct ps4rf_kread_args *))func;
  g_dispatch_calls++;
  return entry(NULL, (struct ps4rf_kread_args *)&wrapper);
#endif
}

int kexec(void *func, void *user_arg) {
  g_kexec_calls++;
  return dispatch_to(func, (void *)&g_wrapper_field_target, (ps4rf_kread_info *)user_arg);
}

/* ------------------------------------------------------------------ case definitions */

enum case_mode { MODE_RUN1 = 0, MODE_GUARD, MODE_DIRECT, MODE_WRITE_SCAN };

struct kcase {
  const char *id;
  const char *name;
  const char *expected;
  int mode;
  uint32_t region_index;
  uint32_t offset;
  uint32_t length;
  uint64_t lstar;
  uint64_t kbase_sdk;
  int expect_run;              /* PS4RF_KREAD_RUN_* (MODE_RUN1 / MODE_GUARD first call)  */
  int expect_cb;               /* PS4RF_KREAD_CB_*                                       */
  int expect_reads;            /* byte reads the case must perform (-1: not checked)     */
  int expect_msr;              /* synthetic LSTAR reads                                   */
  int expect_kexec;            /* kexec() calls                                           */
  int expect_dispatch;         /* callback entries                                        */
  int expect_copied;           /* copied_len written by the callback (0 or the length)   */
  int expect_sha;              /* 1: a measured sha256 must be present                   */
  int expect_flags;            /* expected flags when the callback authenticated         */
  int second_invalid;          /* MODE_GUARD: second request refused pre-kexec            */
  int direct_mode;             /* MODE_DIRECT: 0 standard, 1 decoy                       */
};

#define CASE_COUNT 22

static const struct kcase CASES[CASE_COUNT] = {
    {"A", "valid_read",
     "run=RUN_OK cb=OK copied=min(16,region0.length) reads=that msr=1 kexec=1 dispatch=1 "
     "flags=0xf sha=MEASURED writes=0",
     0, 0u, 0u, 16u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_OK, PS4RF_KREAD_CB_OK, -1, 1, 1, 1,
     -1, 1, 0xF, 0, 0},
    {"B", "zero_length",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0",
     0, 0u, 0u, 0u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"C", "length_max_plus_one",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0",
     0, 0u, 0u, PS4RF_KREAD_MAX_LEN + 1u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"D", "offset_u32_wraparound",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0",
     0, 0u, 0xFFFFFFFFu, 16u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"E", "offset_at_region_end",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0",
     0, 0u, 16u, 1u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"E2", "offset_length_one_over",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0",
     0, 0u, 15u, 2u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"F", "lstar_shape_wrong",
     "run=RUN_CALLBACK cb=LSTAR_SHAPE read_len=0 reads=0 msr=1 kexec=1 writes=0",
     0, 0u, 0u, 8u, SIM_KBASE + 0x1000ull, SIM_KBASE, PS4RF_KREAD_RUN_CALLBACK,
     PS4RF_KREAD_CB_LSTAR_SHAPE, 0, 1, 1, 1, 0, 0, 0, 0, 0},
    {"G", "kbase_cross_check_mismatch",
     "run=RUN_CALLBACK cb=KBASE_MISMATCH read_len=0 reads=0 msr=1 kexec=1 writes=0",
     0, 0u, 0u, 8u, SIM_LSTAR, SIM_KBASE + 0x400000ull, PS4RF_KREAD_RUN_CALLBACK,
     PS4RF_KREAD_CB_KBASE_MISMATCH, 0, 1, 1, 1, 0, 0, 0, 0, 0},
    {"H", "three_calls_after_success",
     "first=RUN_OK second=RUN_ALREADY third=RUN_ALREADY reads_delta=0 msr_delta=0 kexec_delta=0 "
     "dispatch_delta=0",
     1, 0u, 0u, 16u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_OK, PS4RF_KREAD_CB_OK, -1, 1, 1, 1,
     -1, 1, 0xF, 0, 0},
    {"I", "retry_after_refusal",
     "first=RUN_REQUEST_INVALID second=RUN_ALREADY reads_delta=0 msr_delta=0 kexec_delta=0 "
     "dispatch_delta=0",
     1, 0u, 0u, 0u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 1},
    {"J", "dispatch_wrapper_decoy",
     "decoy(magic-valid field 0)=byte-identical real=RUN_OK copied=min(16,region0.length) "
     "decoy_write=0 kernel_writes=0",
     2, 0u, 0u, 16u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_OK, PS4RF_KREAD_CB_OK, -1, 1, 0, 1,
     -1, 1, 0xF, 0, 1},
    {"B2", "callback_zero_length",
     "cb=LENGTH copy=0 reads=0 msr=0 writes=0 (direct dispatch)",
     2, 0u, 0u, 0u, SIM_LSTAR, SIM_KBASE, 0, PS4RF_KREAD_CB_LENGTH, 0, 0, 0, 1, 0, 0, 0, 0, 0},
    {"D2", "callback_wraparound",
     "cb=OVERFLOW copy=0 reads=0 msr=0 writes=0 (direct dispatch)",
     2, 0u, 0xFFFFFFFFu, 16u, SIM_LSTAR, SIM_KBASE, 0, PS4RF_KREAD_CB_OVERFLOW, 0, 0, 0, 1, 0,
     0, 0, 0, 0},
    {"E3", "callback_cross_region",
     "cb=CONTAINMENT copy=0 reads=0 msr=0 writes=0 (direct dispatch)",
     2, 0u, 16u, 1u, SIM_LSTAR, SIM_KBASE, 0, PS4RF_KREAD_CB_CONTAINMENT, 0, 0, 0, 1, 0, 0, 0, 0,
     0},
    {"K", "write_scan_success",
     "run=RUN_OK reads=len kernel_mem_writes=0 cage=OK canary=OK sim=OK",
     3, 0u, 0u, 16u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_OK, PS4RF_KREAD_CB_OK, -1, 1, 1, 1,
     -1, 1, 0xF, 0, 0},
    {"L", "write_scan_refusal",
     "run=RUN_REQUEST_INVALID reads=0 msr=0 kexec=0 kernel_mem_writes=0 cage=OK canary=OK sim=OK",
     3, 0u, 15u, 2u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"M", "boundary_read_at_region_end",
     "run=RUN_OK copied=min(8,region0.length) offset=region0.length-copied sha=MEASURED writes=0",
     0, 0u, 16u, 8u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_OK, PS4RF_KREAD_CB_OK, -1, 1, 1, 1,
     -1, 1, 0xF, 0, 0},
    /* --- W13-C1: the request names the row; these cases exercise the index itself and the
     *     released amd_iommu row (index 1) end to end on the production path --- */
    {"N", "region_index_at_table_end",
     "run=RUN_REGION_INDEX_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0 "
     "(index == region_count: refused before kexec)",
     0, PS4RF_KREAD_REGION_COUNT, 0u, 16u, SIM_LSTAR, SIM_KBASE,
     PS4RF_KREAD_RUN_REGION_INDEX_INVALID, PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"N2", "region_index_wraparound_value",
     "run=RUN_REGION_INDEX_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0 "
     "(0xffffffff is not a row)",
     0, 0xFFFFFFFFu, 0u, 16u, SIM_LSTAR, SIM_KBASE,
     PS4RF_KREAD_RUN_REGION_INDEX_INVALID, PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"O", "amd_iommu_released_window",
     "run=RUN_OK cb=OK copied=16 region=amd_iommu idx=1 reads=16 msr=1 kexec=1 dispatch=1 "
     "flags=0xf sha=MEASURED writes=0",
     0, 1u, 0u, 16u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_OK, PS4RF_KREAD_CB_OK, -1, 1, 1, 1,
     -1, 1, 0xF, 0, 0},
    {"P", "amd_iommu_offset_at_region_end",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0 "
     "(offset == row length)",
     0, 1u, 16u, 1u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {"Q", "amd_iommu_offset_length_one_over",
     "run=RUN_REQUEST_INVALID cb=NOT_RUN reads=0 msr=0 kexec=0 dispatch=0 writes=0 "
     "(offset + length = row length + 1)",
     0, 1u, 15u, 2u, SIM_LSTAR, SIM_KBASE, PS4RF_KREAD_RUN_REQUEST_INVALID,
     PS4RF_KREAD_CB_NOT_RUN, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

/* the case's own row exists? an out-of-range index is a case in its own right (W13-C1) and the
 * helpers must not index the table with it */
static int case_index_valid(const struct kcase *kc) {
  return kc->region_index < PS4RF_KREAD_REGION_COUNT;
}

static uint32_t case_length(const struct kcase *kc) {
  uint32_t region_len;
  if (!case_index_valid(kc)) return kc->length;
  region_len = PS4RF_KREAD_REGIONS[kc->region_index].length;
  if (kc->id[0] == 'M') {
    uint32_t want = kc->length < 8u ? kc->length : 8u;
    return want < region_len ? want : region_len;
  }
  if (kc->length == 0u || kc->length > PS4RF_KREAD_MAX_LEN) return kc->length;
  return kc->length < region_len ? kc->length : region_len;
}

static uint32_t case_offset(const struct kcase *kc) {
  if (!case_index_valid(kc)) return kc->offset;
  if (kc->id[0] == 'M') {
    uint32_t len = case_length(kc);
    return PS4RF_KREAD_REGIONS[kc->region_index].length - len;
  }
  return kc->offset;
}

/* ------------------------------------------------------------------ helpers */

static void reset_sim(const struct kcase *kc) {
  g_lstar = kc->lstar;
  g_kbase_sdk = kc->kbase_sdk;
  g_reads = 0;
  g_msr_reads = 0;
  g_kexec_calls = 0;
  g_dispatch_calls = 0;
  g_read_min = 0xFFFFFFFFu;
  g_read_max = 0u;
  g_bytes_hex[0] = '\0';
  g_sha_hex[0] = '\0';
  memset(&g_wrapper_field_target, 0, sizeof(g_wrapper_field_target));
  g_wrapper_field_target.magic_in = CANARY_MAGIC;
  memset(&g_wrapper_decoy, 0, sizeof(g_wrapper_decoy));
  g_wrapper_decoy.magic_in = PS4RF_KREAD_MAGIC_IN;
  g_wrapper_decoy.kbase_sdk = SIM_KBASE;
  memcpy(&g_decoy_snapshot, &g_wrapper_decoy, sizeof(g_wrapper_decoy));
  memcpy(&g_canary_snapshot, &g_wrapper_field_target, sizeof(g_wrapper_field_target));
}

struct cage {
  uint64_t pre[8];
  ps4rf_kread_info info;
  uint64_t post[8];
};

static void cage_fill(struct cage *cage) {
  for (int i = 0; i < 8; i++) {
    cage->pre[i] = 0xA5A5A5A5A5A5A5A5ull ^ (uint64_t)i;
    cage->post[i] = 0x5A5A5A5A5A5A5A5Aull ^ (uint64_t)i;
  }
}

static int cage_ok(const struct cage *cage) {
  for (int i = 0; i < 8; i++) {
    if (cage->pre[i] != (0xA5A5A5A5A5A5A5A5ull ^ (uint64_t)i)) return 0;
    if (cage->post[i] != (0x5A5A5A5A5A5A5A5Aull ^ (uint64_t)i)) return 0;
  }
  return 1;
}

static int decoy_dirty(void) {
  return memcmp(&g_wrapper_decoy, &g_decoy_snapshot, sizeof(g_wrapper_decoy)) != 0;
}

static int canary_dirty(void) {
  return memcmp(&g_wrapper_field_target, &g_canary_snapshot, sizeof(g_wrapper_field_target)) != 0;
}

static void write_all_or_die(int fd, const char *data, size_t len) {
  size_t off = 0u;
  while (off < len) {
    ssize_t w = write(fd, data + off, len - off);
    if (w <= 0) _exit(4);
    off += (size_t)w;
  }
}

static int emit_json(int fd, const struct kcase *kc, const char *observed, int pass) {
  char line[LINE_MAX];
  int n = snprintf(line, sizeof(line),
                   "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"%s\","
                   "\"pass\":%s}",
                   kc->id, kc->name, kc->expected, observed, pass ? "true" : "false");
  if (n < 0 || (size_t)n >= sizeof(line)) return -1;
  write_all_or_die(fd, line, (size_t)n);
  return pass ? 0 : 1;
}

/* the first table region drives every case: the generator refuses an empty table, so index 0
 * always exists and has length >= 1 */
static void region0_line(char *out, size_t cap) {
  snprintf(out, cap, "region0=%s rva=0x%x len=%u", PS4RF_KREAD_REGIONS[0].name,
           PS4RF_KREAD_REGIONS[0].rva, PS4RF_KREAD_REGIONS[0].length);
}

/* the case's own row: index, region id, compile-time rva and length, straight from the compiled
 * table -- the identity the request names and the event must report (W13-C1) */
static void region_line(const struct kcase *kc, char *out, size_t cap) {
  if (!case_index_valid(kc)) {
    snprintf(out, cap, "region=<none> idx=%u of %u", kc->region_index,
             (unsigned)PS4RF_KREAD_REGION_COUNT);
    return;
  }
  snprintf(out, cap, "region=%s idx=%u rva=0x%x len=%u", PS4RF_KREAD_REGIONS[kc->region_index].name,
           kc->region_index, PS4RF_KREAD_REGIONS[kc->region_index].rva,
           PS4RF_KREAD_REGIONS[kc->region_index].length);
}

/* runs one call through ps4rf_kread_run and reports counters; returns the run result. The case's
 * own region index is what reaches the provider: the table row the request names is the row that
 * is read (W13-C1 moved this from the payload's fixed probe to the request). */
static int call_run(ps4rf_kread_info *info, const struct kcase *kc, uint32_t offset,
                    uint32_t length) {
  return ps4rf_kread_run(info, kc->region_index, offset, length);
}

/* compares the copied bytes against the synthetic pattern */
static int bytes_match(uint32_t rva, const uint8_t *bytes, uint32_t len) {
  for (uint32_t i = 0u; i < len; i++) {
    if (bytes[i] != sim_byte(rva + i)) return 0;
  }
  return 1;
}

static int finish_success_observations(const struct kcase *kc, struct cage *cage,
                                       ps4rf_kread_info *info, uint32_t length, int require_sha,
                                       char *obs, size_t cap) {
  uint32_t rva = PS4RF_KREAD_REGIONS[kc->region_index].rva + case_offset(kc);
  size_t used = strlen(obs);
  int pass = 1;
  if (info->copied_len != length) pass = 0;
  if (!bytes_match(rva, info->bytes, length)) pass = 0;
  hex(info->bytes, length, g_bytes_hex, sizeof(g_bytes_hex));
  snprintf(obs + used, cap - used, " copied=%u rva=0x%x bytes=%s", info->copied_len, rva,
           g_bytes_hex);
  used = strlen(obs);
  if (require_sha) {
    /* the user section measures the SHA-256 of the copied bytes after the callback returned;
     * the callback itself leaves the explicit not-measured marker */
    if (info->sha256_status != PS4RF_KREAD_SHA_MEASURED) pass = 0;
    hex(info->sha256, 32u, g_sha_hex, sizeof(g_sha_hex));
    snprintf(obs + used, cap - used, " sha256_status=MEASURED sha256=%s", g_sha_hex);
  } else {
    /* direct dispatch: no user section ran, so the hash must carry the honest marker */
    if (info->sha256_status != PS4RF_KREAD_SHA_NOT_MEASURED) pass = 0;
    snprintf(obs + used, cap - used, " sha256_status=NOT_MEASURED(user-section only)");
  }
  if (g_reads != (int)length) pass = 0;
  if (g_read_min != rva || g_read_max != rva + length - 1u) pass = 0;
  if (info->flags != 0xFu) pass = 0;
  if (!cage_ok(cage)) pass = 0;
  if (canary_dirty() || decoy_dirty()) pass = 0;
  return pass;
}

/* ------------------------------------------------------------------ case runners */

/* MODE_RUN1, MODE_WRITE_SCAN and the direct-dispatch cases not using the decoy. */
static int run_case_single(int fd, const struct kcase *kc, int write_scan) {
  struct cage cage;
  ps4rf_kread_info *info = &cage.info;
  char obs[OBS_MAX];
  char r0[96];
  char r1[96];
  uint32_t offset = case_offset(kc);
  uint32_t length = case_length(kc);
  uint8_t sim_before[32], sim_after[32];
  int sim_dirty = 0;
  int run;

  (void)write_scan;   /* every case sha256-hashes the simulated kernel around the call */
  reset_sim(kc);
  cage_fill(&cage);
  memset(&cage.info, 0, sizeof(cage.info));
  sim_digest(sim_before);

  run = call_run(info, kc, offset, length);

  sim_digest(sim_after);
  if (memcmp(sim_before, sim_after, 32) != 0) sim_dirty = 1;
  region0_line(r0, sizeof(r0));
  region_line(kc, r1, sizeof(r1));
  snprintf(obs, sizeof(obs),
           "run=%d(%s) cb=%u(%s) kexec_rc=%d read_len=%u copied=%u reads=%d msr=%d kexec=%d "
           "dispatch=%d flags=0x%x cross=%s kernel_mem_writes=%d cage=%s canary=%s sim=%s %s %s",
           run, ps4rf_kread_run_status_name(run), info->cb_status,
           ps4rf_kread_cb_status_name(info->cb_status), (int)info->kexec_rc, info->length,
           info->copied_len, g_reads, g_msr_reads, g_kexec_calls, g_dispatch_calls, info->flags,
           info->cross_check == 1ull ? "MATCH" : "MISMATCH",
           sim_dirty + canary_dirty() + decoy_dirty(), cage_ok(&cage) ? "OK" : "DIRTY",
           canary_dirty() ? "DIRTY" : "OK", sim_dirty ? "DIRTY" : "OK", r0, r1);

  int pass = 1;
  if (run != kc->expect_run) pass = 0;
  if ((int)info->cb_status != kc->expect_cb) pass = 0;
  if (kc->expect_reads >= 0 && g_reads != kc->expect_reads) pass = 0;
  if (g_msr_reads != kc->expect_msr) pass = 0;
  if (kc->expect_kexec >= 0 && g_kexec_calls != kc->expect_kexec) pass = 0;
  if (g_dispatch_calls != kc->expect_dispatch) pass = 0;
  if (sim_dirty || canary_dirty() || decoy_dirty()) pass = 0;
  if (!cage_ok(&cage)) pass = 0;
  if (kc->expect_copied == 0 && info->copied_len != 0u) pass = 0;
  if (run == PS4RF_KREAD_RUN_OK) {
    if (kc->expect_sha) {
      if (!finish_success_observations(kc, &cage, info, length, 1, obs, sizeof(obs))) pass = 0;
    }
    if ((info->flags & kc->expect_flags) != (uint32_t)kc->expect_flags) pass = 0;
  }
  return emit_json(fd, kc, obs, pass);
}

/* MODE_GUARD: a first call (valid or refused), then host-retry style calls that must never
 * reach the kernel again. */
static int run_case_guard(int fd, const struct kcase *kc) {
  struct cage first_cage, second_cage, third_cage;
  ps4rf_kread_info *first = &first_cage.info;
  ps4rf_kread_info *second = &second_cage.info;
  ps4rf_kread_info *third = &third_cage.info;
  char obs[OBS_MAX];
  char r0[96];
  uint32_t length = case_length(kc);
  int run1, run2, run3;
  int reads1, msr1, kexec1, dispatch1;

  reset_sim(kc);
  cage_fill(&first_cage);
  cage_fill(&second_cage);
  cage_fill(&third_cage);
  memset(first, 0, sizeof(*first));
  memset(second, 0, sizeof(*second));
  memset(third, 0, sizeof(*third));

  if (kc->second_invalid) {
    run1 = ps4rf_kread_run(first, kc->region_index, 0u, 0u);   /* refused before kexec */
  } else {
    run1 = ps4rf_kread_run(first, kc->region_index, kc->offset, length);
  }
  reads1 = g_reads;
  msr1 = g_msr_reads;
  kexec1 = g_kexec_calls;
  dispatch1 = g_dispatch_calls;
  /* the host retries: same request twice more (a retry must never invoke the kernel again) */
  run2 = ps4rf_kread_run(second, kc->region_index, kc->offset, length);
  run3 = ps4rf_kread_run(third, kc->region_index, kc->offset, length);

  region0_line(r0, sizeof(r0));
  snprintf(obs, sizeof(obs),
           "first=%d(%s) second=%d(%s) third=%d(%s) reads_delta=%d msr_delta=%d kexec_delta=%d "
           "dispatch_delta=%d first_cb=%u second_magic_out=0x%llx cage_first=%s %s",
           run1, ps4rf_kread_run_status_name(run1), run2, ps4rf_kread_run_status_name(run2),
           run3, ps4rf_kread_run_status_name(run3), g_reads - reads1, g_msr_reads - msr1,
           g_kexec_calls - kexec1, g_dispatch_calls - dispatch1, first->cb_status,
           (unsigned long long)second->magic_out, cage_ok(&first_cage) ? "OK" : "DIRTY", r0);

  int pass = 1;
  if (run1 != kc->expect_run) pass = 0;
  if (run2 != PS4RF_KREAD_RUN_ALREADY || run3 != PS4RF_KREAD_RUN_ALREADY) pass = 0;
  if (g_reads - reads1 != 0 || g_msr_reads - msr1 != 0) pass = 0;
  if (g_kexec_calls - kexec1 != 0) pass = 0;
  if (g_dispatch_calls - dispatch1 != 0) pass = 0;
  if (second->magic_out != 0ull || third->magic_out != 0ull) pass = 0;
  if (!cage_ok(&first_cage) || !cage_ok(&second_cage) || !cage_ok(&third_cage)) pass = 0;
  if (canary_dirty() || decoy_dirty()) pass = 0;
  if (kc->second_invalid == 0 && (int)first->cb_status != kc->expect_cb) pass = 0;
  return emit_json(fd, kc, obs, pass);
}

/* MODE_DIRECT: drive the production callback through the simulated console dispatch without
 * the user-section entry, so the callback's own refusals are exercised. direct_mode 1 uses the
 * decoy (valid caller marker) as wrapper field 0. */
static int run_case_direct(int fd, const struct kcase *kc) {
  struct cage cage;
  ps4rf_kread_info *info = &cage.info;
  char obs[OBS_MAX];
  char r0[96];
  char r1[96];
  uint32_t offset = case_offset(kc);
  uint32_t length = case_length(kc);
  uint8_t sim_before[32], sim_after[32];
  int sim_dirty = 0;
  int rc;

  reset_sim(kc);
  cage_fill(&cage);
  memset(&cage.info, 0, sizeof(cage.info));
  info->magic_in = PS4RF_KREAD_MAGIC_IN;
  info->region_index = kc->region_index;
  info->offset = offset;
  info->length = length;
  info->kbase_sdk = g_kbase_sdk;
  sim_digest(sim_before);

  if (kc->direct_mode == 1) {
    rc = dispatch_to((void *)&ps4rf_kread_kpayload, (void *)&g_wrapper_decoy, info);
  } else {
    rc = dispatch_to((void *)&ps4rf_kread_kpayload, (void *)&g_wrapper_field_target, info);
  }
  sim_digest(sim_after);
  if (memcmp(sim_before, sim_after, 32) != 0) sim_dirty = 1;

  region0_line(r0, sizeof(r0));
  region_line(kc, r1, sizeof(r1));
  snprintf(obs, sizeof(obs),
           "rc=%d cb=%u(%s) magic_out=0x%llx copied=%u reads=%d msr=%d kexec=%d dispatch=%d "
           "decoy_write=%d kernel_writes=%d cage=%s canary=%s sim=%s %s %s",
           rc, info->cb_status, ps4rf_kread_cb_status_name(info->cb_status),
           (unsigned long long)info->magic_out, info->copied_len, g_reads, g_msr_reads,
           g_kexec_calls, g_dispatch_calls, decoy_dirty() ? 1 : 0,
           sim_dirty + canary_dirty() + decoy_dirty(), cage_ok(&cage) ? "OK" : "DIRTY",
           canary_dirty() ? "DIRTY" : "OK", sim_dirty ? "DIRTY" : "OK", r0, r1);

  int pass = 1;
  if ((int)info->cb_status != kc->expect_cb) pass = 0;
  if (kc->expect_reads >= 0 && g_reads != kc->expect_reads) pass = 0;
  if (g_msr_reads != kc->expect_msr) pass = 0;
  if (g_kexec_calls != 0) pass = 0;
  if (g_dispatch_calls != kc->expect_dispatch) pass = 0;
  if (decoy_dirty() || canary_dirty() || sim_dirty) pass = 0;
  if (!cage_ok(&cage)) pass = 0;
  if (kc->expect_cb == PS4RF_KREAD_CB_OK) {
    /* the decoy case runs the full successful read through field 1 */
    if (length == 0u || length > PS4RF_KREAD_MAX_LEN) pass = 0;
    if (kc->direct_mode == 1 &&
        !finish_success_observations(kc, &cage, info, length, 0, obs, sizeof(obs))) pass = 0;
  } else {
    /* a refusal is reported in the payload's own block: the callback started (magic_out) and
     * copied nothing */
    if (info->copied_len != 0u) pass = 0;
    if (info->magic_out != PS4RF_KREAD_MAGIC_OUT) pass = 0;
  }
  return emit_json(fd, kc, obs, pass);
}

/* ------------------------------------------------------------------ child/parent plumbing */

static int emit_case_in_child(const struct kcase *kc, char *out, size_t out_cap) {
  int fds[2];
  pid_t child;
  int status = 0;
  char buf[LINE_MAX];
  size_t used = 0u;

  if (pipe(fds) != 0) {
    snprintf(out, out_cap, "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":"
                           "\"harness error: pipe() failed\",\"pass\":false}",
             kc->id, kc->name, kc->expected);
    printf("%s\n", out);
    return 1;
  }
  child = fork();
  if (child < 0) {
    close(fds[0]);
    close(fds[1]);
    snprintf(out, out_cap, "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":"
                           "\"harness error: fork() failed\",\"pass\":false}",
             kc->id, kc->name, kc->expected);
    printf("%s\n", out);
    return 1;
  }
  if (child == 0) {
    int rc;
    close(fds[0]);
    switch (kc->mode) {
      case MODE_GUARD: rc = run_case_guard(fds[1], kc); break;
      case MODE_DIRECT: rc = run_case_direct(fds[1], kc); break;
      case MODE_WRITE_SCAN: rc = run_case_single(fds[1], kc, 1); break;
      default: rc = run_case_single(fds[1], kc, 0); break;
    }
    close(fds[1]);
    _exit(rc == 0 ? 0 : 1);
  }
  close(fds[1]);
  while (used + 1u < sizeof(buf)) {
    ssize_t r = read(fds[0], buf + used, sizeof(buf) - used - 1u);
    if (r < 0) break;
    if (r == 0) break;
    used += (size_t)r;
  }
  buf[used] = '\0';
  close(fds[0]);
  waitpid(child, &status, 0);

  if (used == 0u) {
    if (WIFSIGNALED(status)) {
      snprintf(out, out_cap,
               "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"harness: "
               "child died on signal %d -- a store through a kbase-derived address cannot be "
               "mapped on the host (a kernel write would fault)\",\"pass\":false}",
               kc->id, kc->name, kc->expected, WTERMSIG(status));
    } else {
      snprintf(out, out_cap,
               "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"harness: "
               "child emitted no case object (wait status 0x%x)\",\"pass\":false}",
               kc->id, kc->name, kc->expected, status);
    }
    printf("%s\n", out);
    return 1;
  }
  snprintf(out, out_cap, "%s", buf);            /* the child's JSON object, verbatim */
  printf("%s\n", out);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
  return 0;
}

int main(void) {
  char objects[CASE_COUNT][LINE_MAX];
  char suite[32768];
  size_t off = 0u;
  int failures = 0;
  size_t i;

  for (i = 0u; i < PS4RF_KREAD_REGION_COUNT; i++) {
    uint64_t end = (uint64_t)PS4RF_KREAD_REGIONS[i].rva + PS4RF_KREAD_REGIONS[i].length;
    if (end > SIM_SIZE) {
      fprintf(stderr, "region %s ends past the simulated kernel (0x%llx > 0x%x)\n",
              PS4RF_KREAD_REGIONS[i].name, (unsigned long long)end, SIM_SIZE);
      return 2;
    }
  }
  sim_fill();

  for (i = 0u; i < CASE_COUNT; i++) {
    failures += emit_case_in_child(&CASES[i], objects[i], sizeof(objects[i]));
  }

  off += (size_t)snprintf(suite + off, sizeof(suite) - off,
                          "{\"suite\":\"w12_kread_offline\",\"cases\":[");
  for (i = 0u; i < CASE_COUNT; i++) {
    off += (size_t)snprintf(suite + off, sizeof(suite) - off, "%s%s", i > 0u ? "," : "",
                            objects[i]);
  }
  (void)snprintf(suite + off, sizeof(suite) - off, "],\"cases_failed\":%d}", failures);
  printf("%s\n", suite);

  return failures == 0 ? 0 : 1;
}
