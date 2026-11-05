/* PS4RF W11.2 offline harness for the fixed privileged boot read.
 *
 * It links the *production* callback path (native/target/ps4rf_bootread.c) and replaces only
 * its leaf operations and the two SDK entry points:
 *
 *   ps4rf_bootread_k_readmsr -> returns the synthetic LSTAR (NEVER executes a real rdmsr)
 *   ps4rf_bootread_k_read8   -> serves the synthetic 16 byte image, counts every byte read
 *   kexec()                  -> simulates the console syscall-11 dispatch and calls the payload
 *   get_kernel_base()        -> returns the synthetic kernel base
 *
 * Everything in between -- the argument block check, the magic markers, the LSTAR shape gate,
 * the kbase cross check, the single fixed 16 byte read, the one-shot guard, the timeval decode
 * and its refusal rules -- is the production code that runs on the console.
 *
 * Synthetic kernel (deterministic, fixed):
 *   kbase         0xffffffff998f4000  (the value the W9 live run observed)
 *   LSTAR         kbase + 0x1c0
 *   image         16 bytes at kbase + 0x224c6c8: int64 tv_sec at +0, int64 tv_usec at +8
 *   get_kernel_base() returns the synthetic kbase (case G returns a different one)
 *
 * Dispatch ABI: the kernel-side shape the console actually uses (proven live by the W9
 * attestation run in this repository, documented in ps4rf_attest.h and by the GoldHEN
 * syscall-11 wrapper): the kernel builds { void *syscall_handler; payload } and passes a
 * pointer to that wrapper to the callback; the caller's payload pointer sits in the SECOND
 * field. run() passes the caller's own info block as the payload, so a console-correct
 * callback reads its argument block from wrapper + 8. The harness reproduces exactly that
 * dispatch; it does not invent a friendlier one.
 *
 * The wrapper's syscall_handler field is a kernel code address on the console. On the host no
 * kernel mapping exists, so the synthetic kernel points it at a harness-owned block with a
 * wrong magic canary: a correct callback ignores the field entirely, while a callback that
 * misreads the wrapper's FIRST field as its argument block will (a) read the canary as the
 * caller marker and (b) write cb_status into it -- the harness detects both. On the real
 * console that same misread would read and write kernel memory (the write is carried by the
 * CB_MAGIC refusal path), which is exactly the class of bug this harness must catch.
 *
 * Cases (each in its own child process: a fresh process is a fresh one-shot session):
 *   A  valid timeval               -> RUN_OK, read_len 16, cross_check MATCH
 *   B  tv_sec <= 0                 -> RUN_TIMEVAL_INVALID / TV_SEC_NONPOSITIVE
 *   C  tv_usec < 0                 -> RUN_TIMEVAL_INVALID / TV_USEC_NEGATIVE
 *   D  tv_usec >= 1000000          -> RUN_TIMEVAL_INVALID / TV_USEC_OUT_OF_RANGE
 *   E  boottime > wall clock       -> RUN_IMPLAUSIBLE / BOOT_TIME_AFTER_WALL_CLOCK
 *   F  LSTAR shape wrong           -> CB_LSTAR_SHAPE, zero bytes read
 *   G  kbase cross-check mismatch  -> CB_KBASE_MISMATCH, zero bytes read
 *   H  second call in the same process after a successful run -> RUN_ALREADY, zero reads
 *
 * Output: one JSON object per case, then one summary line;
 *   {"suite":"w11_2_bootread_offline","cases":[...],"cases_failed":N}
 * Exit code 0 only when every case passed. Build and run: tests/test_bootread_offline.py
 * (same convention as the W9 harness). Offline only: no network, no console, no rdmsr.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ps4rf_bootread.h"
#include "ps4rf_libc.h"

#define SIM_KBASE 0xffffffff998f4000ull
#define SIM_LSTAR (SIM_KBASE + 0x1c0ull)
#define SIM_RVA 0x224c6c8u
#define SIM_WALL 1789910300ll
#define SIM_SEC 1789910256ll
#define SIM_USEC 860896ll

#define CANARY_MAGIC 0xDEADBEEFu
#define OBS_MAX 768
#define LINE_MAX 1280
#define CASE_COUNT 8

/* ------------------------------------------------------------------ synthetic state */

static uint64_t g_lstar = SIM_LSTAR;
static uint64_t g_kbase_sdk = SIM_KBASE;
static uint8_t g_image[PS4RF_BOOTREAD_READ_LEN];
static int g_reads;          /* ps4rf_bootread_k_read8 calls (byte reads)            */
static int g_msr_reads;      /* ps4rf_bootread_k_readmsr calls (synthetic LSTAR reads) */
static int g_kexec_calls;    /* kexec() calls                                        */

/* The synthetic kernel's syscall_handler target: never a real kernel address on the host.
 * A console-correct payload never touches it; a misreading payload lands here (see header). */
static ps4rf_bootread_info g_wrapper_field_target;

static int wrapper_misread_detected(void) {
  return g_wrapper_field_target.cb_status == PS4RF_BOOTREAD_CB_MAGIC ||
         g_wrapper_field_target.magic_in != CANARY_MAGIC;
}

/* ------------------------------------------------------------------ leaf replacements */

uint64_t ps4rf_bootread_k_readmsr(uint32_t reg) {
  g_msr_reads++;
  if (reg != 0xC0000082u) {
    fprintf(stderr, "unexpected MSR 0x%x requested\n", reg);
    _exit(3);
  }
  return g_lstar;
}

uint8_t ps4rf_bootread_k_read8(uint64_t base, uint32_t rva) {
  g_reads++;
  if (base != SIM_KBASE || rva < SIM_RVA || rva >= SIM_RVA + PS4RF_BOOTREAD_READ_LEN) {
    fprintf(stderr, "read outside the simulated image: 0x%llx + 0x%x\n",
            (unsigned long long)base, rva);
    _exit(3);
  }
  return g_image[rva - SIM_RVA];
}

/* ------------------------------------------------------------------ SDK entry points */

uint64_t get_kernel_base(void) { return g_kbase_sdk; }

int kexec(void *func, void *user_arg) {
  /* the console dispatch: { void *syscall_handler; payload } with the caller's pointer in the
   * second field; the payload is called with a pointer to this wrapper, exactly like the SDK's
   * kpayload path (see ps4rf_attest.h and the W9 live run) */
  struct kernel_abi {
    void *syscall_handler;
    ps4rf_bootread_info *info;
  } wrapper;
  int (*entry)(void *, struct ps4rf_bootread_args *);
  g_kexec_calls++;
  wrapper.syscall_handler = (void *)&g_wrapper_field_target;
  wrapper.info = (ps4rf_bootread_info *)user_arg;
  entry = (int (*)(void *, struct ps4rf_bootread_args *))func;
  return entry(NULL, (struct ps4rf_bootread_args *)&wrapper);
}

/* ------------------------------------------------------------------ case definitions */

struct bcase {
  const char *id;                 /* "A" .. "H"                                        */
  const char *name;               /* short machine-readable name                       */
  const char *expected;           /* the contract, as printed in the JSON              */
  long long sec;
  long long usec;
  long long wall;
  uint64_t lstar;
  uint64_t kbase_sdk;
  int expect_run;                 /* PS4RF_BOOTREAD_RUN_*                              */
  int expect_cb;                  /* PS4RF_BOOTREAD_CB_*                               */
  const char *expect_validation;  /* NULL: not checked (callback stopped before decode) */
  int expect_reads;               /* byte reads the case must perform                  */
  int expect_read_len;            /* 16 or 0                                           */
  int expect_cross;               /* 1, 0; covered by expect_run/expect_cb when stopped */
  int two_shot;                   /* H: a second call must be refused after a success  */
};

static const struct bcase CASES[CASE_COUNT] = {
    {"A", "valid_timeval",
     "run=PS4RF_BOOTREAD_RUN_OK read_len=16 cross_check=MATCH validation=OK reads=16",
     SIM_SEC, SIM_USEC, SIM_WALL, SIM_LSTAR, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_OK, PS4RF_BOOTREAD_CB_OK, PS4RF_BOOTREAD_VAL_OK, 16, 16, 1, 0},
    {"B", "tv_sec_nonpositive",
     "run=PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID validation=TV_SEC_NONPOSITIVE reads=16",
     0ll, SIM_USEC, SIM_WALL, SIM_LSTAR, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID, PS4RF_BOOTREAD_CB_OK, PS4RF_BOOTREAD_VAL_SEC, 16, 16,
     1, 0},
    {"C", "tv_usec_negative",
     "run=PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID validation=TV_USEC_NEGATIVE reads=16",
     SIM_SEC, -1ll, SIM_WALL, SIM_LSTAR, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID, PS4RF_BOOTREAD_CB_OK, PS4RF_BOOTREAD_VAL_USEC_NEG, 16,
     16, 1, 0},
    {"D", "tv_usec_out_of_range",
     "run=PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID validation=TV_USEC_OUT_OF_RANGE reads=16",
     SIM_SEC, 1000000ll, SIM_WALL, SIM_LSTAR, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID, PS4RF_BOOTREAD_CB_OK, PS4RF_BOOTREAD_VAL_USEC_RANGE, 16,
     16, 1, 0},
    {"E", "boot_time_after_wall_clock",
     "run=PS4RF_BOOTREAD_RUN_IMPLAUSIBLE validation=BOOT_TIME_AFTER_WALL_CLOCK reads=16",
     SIM_WALL + 1ll, SIM_USEC, SIM_WALL, SIM_LSTAR, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_IMPLAUSIBLE, PS4RF_BOOTREAD_CB_OK, PS4RF_BOOTREAD_VAL_FUTURE, 16, 16, 1,
     0},
    {"F", "lstar_shape_wrong",
     "cb=PS4RF_BOOTREAD_CB_LSTAR_SHAPE read_len=0 read_count=0 reads=0",
     SIM_SEC, SIM_USEC, SIM_WALL, SIM_KBASE + 0x1000ull, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_CALLBACK, PS4RF_BOOTREAD_CB_LSTAR_SHAPE, NULL, 0, 0, 0, 0},
    {"G", "kbase_cross_check_mismatch",
     "cb=PS4RF_BOOTREAD_CB_KBASE_MISMATCH read_len=0 read_count=0 reads=0",
     SIM_SEC, SIM_USEC, SIM_WALL, SIM_LSTAR, SIM_KBASE + 0x400000ull,
     PS4RF_BOOTREAD_RUN_CALLBACK, PS4RF_BOOTREAD_CB_KBASE_MISMATCH, NULL, 0, 0, 0, 0},
    {"H", "second_call_refused",
     "second_call=PS4RF_BOOTREAD_RUN_ALREADY reads_delta=0 kexec_calls_delta=0",
     SIM_SEC, SIM_USEC, SIM_WALL, SIM_LSTAR, SIM_KBASE,
     PS4RF_BOOTREAD_RUN_OK, PS4RF_BOOTREAD_CB_OK, PS4RF_BOOTREAD_VAL_OK, 16, 16, 1, 1},
};

/* ------------------------------------------------------------------ helpers */

static void reset_sim(const struct bcase *bc) {
  g_lstar = bc->lstar;
  g_kbase_sdk = bc->kbase_sdk;
  g_reads = 0;
  g_msr_reads = 0;
  g_kexec_calls = 0;
  memset(g_image, 0, sizeof(g_image));
  memcpy(&g_image[0], &bc->sec, 8);
  memcpy(&g_image[8], &bc->usec, 8);
  memset(&g_wrapper_field_target, 0, sizeof(g_wrapper_field_target));
  g_wrapper_field_target.magic_in = CANARY_MAGIC;
}

static void append_misread_note(char *obs, size_t cap) {
  if (!wrapper_misread_detected()) return;
  size_t used = strlen(obs);
  snprintf(obs + used, cap - used,
           "; dispatch-misread: the callback read the syscall-11 wrapper's first field "
           "(syscall_handler) as its argument block (canary cb_status=%u); the console wrapper "
           "stores the caller's block in the second field (offset 8, the live-verified W9 shape)",
           g_wrapper_field_target.cb_status);
}

static int write_all(int fd, const char *data, size_t len) {
  size_t off = 0u;
  while (off < len) {
    ssize_t w = write(fd, data + off, len - off);
    if (w <= 0) return -1;
    off += (size_t)w;
  }
  return 0;
}

static int emit_json(int fd, const struct bcase *bc, const char *observed, int pass) {
  char line[LINE_MAX];
  int n = snprintf(line, sizeof(line),
                   "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"%s\","
                   "\"pass\":%s}",
                   bc->id, bc->name, bc->expected, observed, pass ? "true" : "false");
  if (n < 0 || (size_t)n >= sizeof(line)) return -1;
  return write_all(fd, line, (size_t)n);
}

/* one-shot case: A..G. Returns 1 when the case passed. */
static int run_case_once_emit(int fd, const struct bcase *bc) {
  char obs[OBS_MAX];
  ps4rf_bootread_info info;
  ps4rf_bootread_decoded dec;
  int pass = 1;

  reset_sim(bc);
  memset(&info, 0, sizeof(info));
  memset(&dec, 0, sizeof(dec));

  int run = ps4rf_bootread_run(&info, bc->wall);
  (void)ps4rf_bootread_decode(&info, &dec, bc->wall);
  const char *validation = dec.validation != NULL ? dec.validation : PS4RF_BOOTREAD_VAL_NOT_READ;

  snprintf(obs, sizeof(obs),
           "run=%d(%s) cb=%u(%s) kexec_rc=%d read_len=%u read_count=%u cross=%s reads=%d "
           "msr_reads=%d validation=%s",
           run, ps4rf_bootread_run_status_name(run), info.cb_status,
           ps4rf_bootread_cb_status_name(info.cb_status), (int)info.kexec_rc, info.read_len,
           info.read_count, info.cross_check == 1ull ? "MATCH" : "MISMATCH", g_reads, g_msr_reads,
           validation);
  append_misread_note(obs, sizeof(obs));

  if (run != bc->expect_run) pass = 0;
  if ((int)info.cb_status != bc->expect_cb) pass = 0;
  if ((int)info.read_len != bc->expect_read_len) pass = 0;
  if (info.read_count != (bc->expect_read_len == 16 ? 1u : 0u)) pass = 0;
  if (g_reads != bc->expect_reads) pass = 0;
  if (g_msr_reads != 1) pass = 0;
  if (g_kexec_calls != 1) pass = 0;
  if ((int)info.cross_check != bc->expect_cross) pass = 0;
  if (bc->expect_validation != NULL && strcmp(validation, bc->expect_validation) != 0) pass = 0;
  if (bc->expect_read_len == 16) {
    if (memcmp(info.raw, g_image, PS4RF_BOOTREAD_READ_LEN) != 0) pass = 0;
    if (dec.tv_sec != bc->sec || dec.tv_usec != bc->usec) pass = 0;
  }
  if (wrapper_misread_detected()) pass = 0;

  return emit_json(fd, bc, obs, pass) == 0 ? pass : 0;
}

/* two-shot case H: a successful first run, then a second call that must be refused with no
 * kernel traffic at all (no kexec, no MSR read, no byte read). */
static int run_case_two_shot_emit(int fd, const struct bcase *bc) {
  char obs[OBS_MAX];
  ps4rf_bootread_info first;
  ps4rf_bootread_info second;
  ps4rf_bootread_decoded dec;
  int pass = 1;

  reset_sim(bc);
  memset(&first, 0, sizeof(first));
  memset(&second, 0, sizeof(second));
  memset(&dec, 0, sizeof(dec));

  int first_run = ps4rf_bootread_run(&first, bc->wall);
  (void)ps4rf_bootread_decode(&first, &dec, bc->wall);
  int first_reads = g_reads;
  int first_msr = g_msr_reads;
  int first_kexec = g_kexec_calls;
  int misread_first = wrapper_misread_detected();

  int second_run = ps4rf_bootread_run(&second, bc->wall);
  int reads_delta = g_reads - first_reads;
  int msr_delta = g_msr_reads - first_msr;
  int kexec_delta = g_kexec_calls - first_kexec;

  snprintf(obs, sizeof(obs),
           "first_run=%d(%s) second_call=%d(%s) reads_delta=%d msr_reads_delta=%d "
           "kexec_calls_delta=%d",
           first_run, ps4rf_bootread_run_status_name(first_run), second_run,
           ps4rf_bootread_run_status_name(second_run), reads_delta, msr_delta, kexec_delta);
  append_misread_note(obs, sizeof(obs));

  if (first_run != PS4RF_BOOTREAD_RUN_OK) {
    pass = 0;
    size_t used = strlen(obs);
    snprintf(obs + used, sizeof(obs) - used,
             "; precondition not met: case H requires a successful first run");
  }
  if (second_run != PS4RF_BOOTREAD_RUN_ALREADY) pass = 0;
  if (reads_delta != 0) pass = 0;
  if (msr_delta != 0) pass = 0;
  if (kexec_delta != 0) pass = 0;
  if (misread_first || wrapper_misread_detected()) pass = 0;
  if (first.read_len != PS4RF_BOOTREAD_READ_LEN || first.cross_check != 1ull) pass = 0;

  return emit_json(fd, bc, obs, pass) == 0 ? pass : 0;
}

/* ------------------------------------------------------------------ child/parent plumbing */

static int emit_case_in_child(const struct bcase *bc, char *out, size_t out_cap) {
  int fds[2];
  pid_t child;
  int status = 0;
  char buf[LINE_MAX];
  size_t used = 0u;

  if (pipe(fds) != 0) {
    snprintf(out, out_cap,
             "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"harness error: "
             "pipe() failed\",\"pass\":false}",
             bc->id, bc->name, bc->expected);
    printf("%s\n", out);
    return 1;
  }
  child = fork();
  if (child < 0) {
    close(fds[0]);
    close(fds[1]);
    snprintf(out, out_cap,
             "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"harness error: "
             "fork() failed\",\"pass\":false}",
             bc->id, bc->name, bc->expected);
    printf("%s\n", out);
    return 1;
  }
  if (child == 0) {
    int pass;
    close(fds[0]);
    pass = bc->two_shot ? run_case_two_shot_emit(fds[1], bc) : run_case_once_emit(fds[1], bc);
    close(fds[1]);
    _exit(pass ? 0 : 1);
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
    snprintf(out, out_cap,
             "{\"case\":\"%s\",\"name\":\"%s\",\"expected\":\"%s\",\"observed\":\"harness: child "
             "emitted no case object (wait status 0x%x)\",\"pass\":false}",
             bc->id, bc->name, bc->expected, status);
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
  char suite[16384];
  size_t off = 0u;
  int failures = 0;
  size_t i;

  for (i = 0u; i < CASE_COUNT; i++) {
    failures += emit_case_in_child(&CASES[i], objects[i], sizeof(objects[i]));
  }

  off += (size_t)snprintf(suite + off, sizeof(suite) - off,
                          "{\"suite\":\"w11_2_bootread_offline\",\"cases\":[");
  for (i = 0u; i < CASE_COUNT; i++) {
    off += (size_t)snprintf(suite + off, sizeof(suite) - off, "%s%s", i > 0u ? "," : "",
                            objects[i]);
  }
  (void)snprintf(suite + off, sizeof(suite) - off, "],\"cases_failed\":%d}", failures);
  printf("%s\n", suite);

  return failures == 0 ? 0 : 1;
}
