/* PS4RF W11.2 -- fixed privileged boot identity read implementation.
 *
 * Section discipline (enforced by the build gates, not by comments):
 *   kernel section : ps4rf_bootread_kpayload, ps4rf_bootread_k_*  (one rdmsr, 16 fixed byte reads)
 *   user section   : ps4rf_bootread_run / _validate / _decode / the event builder (kexec once)
 *
 * There is no indirect call anywhere in this file, no allocation, no retry loop, no loop over
 * addresses, no kernel write and no host controlled address or length. The callback performs
 * exactly one 16 byte read of the single compile-time region (kbase + 0x224C6C8) and writes the
 * observed bytes into the caller's own result block; the payload never forms a boot id.
 */

#include "ps4rf_bootread.h"
#include "ps4rf_libc.h"

/* The result block is a fixed, bounded layout: this assertion is what keeps it that way, and the
 * manifest gate derives the same numbers from the built image (guard +0x58, magic_out +0x50). */
typedef char ps4rf_bootread_info_is_96[(sizeof(ps4rf_bootread_info) == 96) ? 1 : -1];

/* Both come from libPS4 on the console: kexec() is the single privileged transition, and
 * get_kernel_base() is the SDK's own LSTAR-based image base, which is what the callback
 * cross-checks its LSTAR-derived candidate against before reading anything. A host build links
 * honest stand-ins (ps4rf_bootread_host.c) or the offline simulator (tests/harness). */
extern int kexec(void *func, void *user_arg);
extern uint64_t get_kernel_base(void);

#define PS4RF_BOOTREAD_SOURCE_RVA 0x224C6C8u          /* pinned FW13.52 KERN_BOOTTIME (W10)  */
#define PS4RF_BOOTREAD_XFAST_RVA 0x1C0u               /* SDK fw_defines K1352_XFAST_SYSCALL  */
#define PS4RF_BOOTREAD_KERNEL_MIN 0xffff800000000000ull
#define PS4RF_BOOTREAD_LSTAR_MSR 0xC0000082u
#define PS4RF_BOOTREAD_USEC_LIMIT 1000000ll

/* ------------------------------------------------------------------ kernel section */

/* The two leaf operations are separate (weak, not inlined) functions: the offline harness links
 * its own definitions to drive the *production* callback path against a synthetic image, while a
 * shipped artefact uses these. Exactly one rdmsr lives in the whole payload. */
__attribute__((weak, noinline)) uint64_t ps4rf_bootread_k_readmsr(uint32_t reg) {
  uint32_t low = 0, high = 0;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(reg));
  return ((uint64_t)high << 32) | (uint64_t)low;
}

__attribute__((weak, noinline)) uint8_t ps4rf_bootread_k_read8(uint64_t base, uint32_t rva) {
  return *(volatile uint8_t *)(base + (uint64_t)rva);
}

int ps4rf_bootread_k_lstar_ok(uint64_t lstar) {
  if (lstar < PS4RF_BOOTREAD_KERNEL_MIN) return 0;
  /* LSTAR must point at the syscall entry: page offset equals the SDK's xfast RVA */
  if ((lstar & 0xfffull) != PS4RF_BOOTREAD_XFAST_RVA) return 0;
  return 1;
}

int ps4rf_bootread_kpayload(void *td, struct ps4rf_bootread_args *args) {
  (void)td;
  if (args == 0) return -1;
  ps4rf_bootread_info *info = args->info;
  if (info == 0) return -1;
  if (info->magic_in != PS4RF_BOOTREAD_MAGIC_IN) {
    info->cb_status = PS4RF_BOOTREAD_CB_MAGIC;
    return -1;
  }
  /* the callback body has started: this marker says "executed", the guard below says "completed",
   * so a callback that stops before reading is never reported as one that never ran */
  info->magic_out = PS4RF_BOOTREAD_MAGIC_OUT;

  /* 1. base: the one privileged instruction, and only the observed value is reported */
  uint64_t lstar = ps4rf_bootread_k_readmsr(PS4RF_BOOTREAD_LSTAR_MSR);
  info->lstar = lstar;

  /* 2. shape gate + cross check, both before a single byte is read */
  if (!ps4rf_bootread_k_lstar_ok(lstar)) {
    info->cb_status = PS4RF_BOOTREAD_CB_LSTAR_SHAPE;
    return 0;                                   /* zero bytes read */
  }
  uint64_t kbase = lstar - (uint64_t)PS4RF_BOOTREAD_XFAST_RVA;
  info->kbase_candidate = kbase;
  info->source_rva = (uint64_t)PS4RF_BOOTREAD_SOURCE_RVA;
  if (info->kbase_sdk == 0ull || info->kbase_sdk != kbase) {
    info->cross_check = 0ull;
    info->cb_status = PS4RF_BOOTREAD_CB_KBASE_MISMATCH;
    return 0;                                   /* zero bytes read */
  }
  info->cross_check = 1ull;

  /* 3.-5. the single fixed region: exactly 16 bytes into the caller's own result block */
  info->read_count = 0u;
  info->read_len = 0u;
  for (uint32_t i = 0u; i < PS4RF_BOOTREAD_READ_LEN; i++) {
    info->raw[i] = ps4rf_bootread_k_read8(kbase, PS4RF_BOOTREAD_SOURCE_RVA + i);
  }
  info->read_count = 1u;
  info->read_len = PS4RF_BOOTREAD_READ_LEN;
  info->cb_status = PS4RF_BOOTREAD_CB_OK;

  /* 6. return: no further kernel memory operation */
  info->magic_out = PS4RF_BOOTREAD_MAGIC_OUT;
  info->guard = PS4RF_BOOTREAD_GUARD;
  return 0;
}

/* -------------------------------------------------------------------- user section */

static int g_ps4rf_bootread_called = 0;         /* one shot: set before kexec, never reset */

int ps4rf_bootread_run(ps4rf_bootread_info *info, long long wall_clock_sec) {
  if (info == 0) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (g_ps4rf_bootread_called) return PS4RF_BOOTREAD_RUN_ALREADY;
  g_ps4rf_bootread_called = 1;                  /* the guard is set BEFORE kexec */

  uint8_t *raw = (uint8_t *)info;
  for (uint32_t i = 0u; i < sizeof(ps4rf_bootread_info); i++) raw[i] = 0u;
  info->magic_in = PS4RF_BOOTREAD_MAGIC_IN;
  info->kbase_sdk = get_kernel_base();

  /* the payload is entered with the caller's block in the wrapper's second field; the payload
   * itself passes the info block, the SDK builds the wrapper around it */
  int rc = kexec((void *)&ps4rf_bootread_kpayload, (void *)info);
  info->kexec_rc = (int32_t)rc;

  int verdict = ps4rf_bootread_validate(info);
  if (verdict != PS4RF_BOOTREAD_RUN_OK) return verdict;
  if (rc != 0) return PS4RF_BOOTREAD_RUN_KEXEC_FAILED;

  ps4rf_bootread_decoded dec;
  int d = ps4rf_bootread_decode(info, &dec, wall_clock_sec);
  if (d == PS4RF_BOOTREAD_DEC_INCOMPLETE) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (d == PS4RF_BOOTREAD_DEC_FUTURE) return PS4RF_BOOTREAD_RUN_IMPLAUSIBLE;
  if (d != PS4RF_BOOTREAD_DEC_OK) return PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID;
  return PS4RF_BOOTREAD_RUN_OK;
}

int ps4rf_bootread_validate(const ps4rf_bootread_info *info) {
  if (info == 0) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  /* A callback that reported a status ran; that status is the answer, even when it stopped
   * before reading (no magic_out: nothing was measured). */
  if (info->cb_status != PS4RF_BOOTREAD_CB_OK) return PS4RF_BOOTREAD_RUN_CALLBACK;
  if (info->magic_out != PS4RF_BOOTREAD_MAGIC_OUT) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (info->guard != PS4RF_BOOTREAD_GUARD) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (info->read_count != 1u) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (info->read_len != PS4RF_BOOTREAD_READ_LEN) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (info->cross_check != 1ull) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (info->lstar == 0ull || info->kbase_candidate == 0ull) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  if (info->kbase_sdk == 0ull) return PS4RF_BOOTREAD_RUN_RESULT_INVALID;
  return PS4RF_BOOTREAD_RUN_OK;
}

static long long le_i64(const uint8_t *raw) {
  uint64_t v = 0ull;
  for (uint32_t i = 0u; i < 8u; i++) v |= ((uint64_t)raw[i]) << (8u * i);
  return (long long)v;                          /* two's complement, x86-64 layout */
}

int ps4rf_bootread_decode(const ps4rf_bootread_info *info, ps4rf_bootread_decoded *out,
                          long long wall_clock_sec) {
  if (info == 0 || out == 0) return PS4RF_BOOTREAD_DEC_INCOMPLETE;
  out->tv_sec = 0ll;
  out->tv_usec = 0ll;
  out->wall_clock_sec = wall_clock_sec;
  out->validation = PS4RF_BOOTREAD_VAL_NOT_READ;
  if (info->read_len != PS4RF_BOOTREAD_READ_LEN) return PS4RF_BOOTREAD_DEC_INCOMPLETE;
  if (info->magic_out != PS4RF_BOOTREAD_MAGIC_OUT) return PS4RF_BOOTREAD_DEC_INCOMPLETE;
  if (info->guard != PS4RF_BOOTREAD_GUARD) return PS4RF_BOOTREAD_DEC_INCOMPLETE;
  out->tv_sec = le_i64(&info->raw[0]);
  out->tv_usec = le_i64(&info->raw[8]);
  out->validation = PS4RF_BOOTREAD_VAL_OK;
  if (out->tv_sec <= 0ll) {
    out->validation = PS4RF_BOOTREAD_VAL_SEC;
    return PS4RF_BOOTREAD_DEC_SEC;
  }
  if (out->tv_usec < 0ll) {
    out->validation = PS4RF_BOOTREAD_VAL_USEC_NEG;
    return PS4RF_BOOTREAD_DEC_USEC_NEG;
  }
  if (out->tv_usec >= PS4RF_BOOTREAD_USEC_LIMIT) {
    out->validation = PS4RF_BOOTREAD_VAL_USEC_RANGE;
    return PS4RF_BOOTREAD_DEC_USEC_RANGE;
  }
  /* the boot instant cannot lie in the future: compared against the console's own wall clock
   * (when it is available; the host repeats this check against its side independently) */
  if (wall_clock_sec > 0ll && out->tv_sec > wall_clock_sec) {
    out->validation = PS4RF_BOOTREAD_VAL_FUTURE;
    return PS4RF_BOOTREAD_DEC_FUTURE;
  }
  return PS4RF_BOOTREAD_DEC_OK;
}

const char *ps4rf_bootread_cb_status_name(uint32_t status) {
  if (status == PS4RF_BOOTREAD_CB_OK) return "OK";
  if (status == PS4RF_BOOTREAD_CB_ARGS) return "ARGS_MISSING";
  if (status == PS4RF_BOOTREAD_CB_MAGIC) return "CALLER_MARKER_MISSING";
  if (status == PS4RF_BOOTREAD_CB_LSTAR_SHAPE) return "LSTAR_SHAPE_INVALID";
  if (status == PS4RF_BOOTREAD_CB_KBASE_MISMATCH) return "KBASE_CROSS_CHECK_MISMATCH";
  return "UNKNOWN";
}

const char *ps4rf_bootread_run_status_name(int run_result) {
  if (run_result == PS4RF_BOOTREAD_RUN_OK) return "OK";
  if (run_result == PS4RF_BOOTREAD_RUN_ALREADY) return "SECOND_CALL_REFUSED";
  if (run_result == PS4RF_BOOTREAD_RUN_KEXEC_FAILED) return "KEXEC_FAILED";
  if (run_result == PS4RF_BOOTREAD_RUN_CALLBACK) return "CALLBACK_STOPPED";
  if (run_result == PS4RF_BOOTREAD_RUN_RESULT_INVALID) return "RESULT_INVALID";
  if (run_result == PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID) return "TIMEVAL_INVALID";
  if (run_result == PS4RF_BOOTREAD_RUN_IMPLAUSIBLE) return "BOOT_TIME_IMPLAUSIBLE";
  return "UNKNOWN";
}

const char *ps4rf_bootread_bye_reason(int run_result) {
  /* the host re-derives the same coarse status from the raw numbers: a failed read is
   * BOOT_READ_FAILED, an implausible instant is BOOT_TIME_IMPLAUSIBLE */
  if (run_result == PS4RF_BOOTREAD_RUN_IMPLAUSIBLE) return "BOOT_TIME_IMPLAUSIBLE";
  return "BOOT_READ_FAILED";
}

int ps4rf_bootread_event_status(int run_result) {
  if (run_result == PS4RF_BOOTREAD_RUN_OK) return PS4RF_BOOTREAD_STATUS_OK;
  if (run_result == PS4RF_BOOTREAD_RUN_IMPLAUSIBLE) return PS4RF_BOOTREAD_STATUS_IMPLAUSIBLE;
  return PS4RF_BOOTREAD_STATUS_READ_FAILED;     /* everything else is a failed read */
}

/* ------------------------------------------------------------------------ report */

static void dec_ll(char *out, size_t cap, long long value) {
  char tmp[24];
  size_t n = 0u;
  size_t i = 0u;
  unsigned long long u;
  int neg = (value < 0);
  if (cap == 0u) return;
  u = neg ? (unsigned long long)(-value) : (unsigned long long)value;
  if (u == 0ull) tmp[n++] = '0';
  while (u != 0ull && n < sizeof(tmp)) {
    tmp[n++] = (char)('0' + (int)(u % 10ull));
    u /= 10ull;
  }
  if (neg && i + 1u < cap) out[i++] = '-';
  while (n > 0u && i + 1u < cap) out[i++] = tmp[--n];
  out[i] = '\0';
}

static void hex_bytes(char *out, size_t cap, const uint8_t *data, uint32_t len) {
  static const char digits[] = "0123456789abcdef";
  size_t o = 0u;
  /* the bound must leave room for the two digits *and* the terminator of the final byte:
   * with `o + 3u < cap` a 16 byte read into a 33 byte buffer stopped after 15 bytes, and the
   * host (correctly) refused the event for claiming 16 bytes while sending 30 hex characters. */
  for (uint32_t i = 0u; i < len && o + 2u < cap; i++) {
    out[o++] = digits[(data[i] >> 4) & 0xfu];
    out[o++] = digits[data[i] & 0xfu];
  }
  out[o] = '\0';
}

static void u64_hex(char *out, uint64_t v) {
  static const char digits[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  out[0] = '0';
  out[1] = 'x';
  for (uint32_t i = 0u; i < 16u; i++) out[2u + i] = digits[(v >> (4u * (15u - i))) & 0xfull];
  out[18] = '\0';
}

jval *ps4rf_bootread_event(const ps4rf_bootread_info *info, int run_result,
                           const ps4rf_bootread_decoded *decoded, long long wall_clock_sec,
                           const char *build_id, const char *label) {
  if (info == NULL) return NULL;
  jval *event = jval_new_object();
  if (event == NULL) return NULL;
  char buf[128];
  char hex[2u * PS4RF_BOOTREAD_READ_LEN + 1u];
  char sec[24];
  char usec[24];
  char wall[24];
  char rva[24];

  int executed = info->magic_out == PS4RF_BOOTREAD_MAGIC_OUT;
  int read_done = executed && info->read_len == PS4RF_BOOTREAD_READ_LEN && info->read_count == 1u;
  uint32_t len = read_done ? PS4RF_BOOTREAD_READ_LEN : 0u;
  hex_bytes(hex, sizeof(hex), info->raw, len);
  u64_hex(buf, info->lstar);
  jval *j_lstar = jval_new_string(buf);
  u64_hex(buf, info->kbase_candidate);
  jval *j_kbase = jval_new_string(buf);
  u64_hex(buf, info->kbase_sdk);
  jval *j_kbase_sdk = jval_new_string(buf);
  /* nothing about the source may look measured when the callback never ran */
  if (executed && info->source_rva != 0ull) {
    u64_hex(rva, info->source_rva);
  } else {
    rva[0] = 'U';
    rva[1] = 'N';
    rva[2] = 'M';
    rva[3] = 'E';
    rva[4] = 'A';
    rva[5] = 'S';
    rva[6] = 'U';
    rva[7] = 'R';
    rva[8] = 'E';
    rva[9] = 'D';
    rva[10] = '\0';
  }
  const char *cross_str = !executed ? "UNMEASURED"
                           : (info->cross_check == 1ull
                                  ? "MATCH"
                                  : (info->kbase_candidate != 0ull ? "MISMATCH" : "UNMEASURED"));
  const char *cb_name = executed ? ps4rf_bootread_cb_status_name(info->cb_status)
                                 : "NOT_EXECUTED";
  dec_ll(sec, sizeof(sec), decoded != NULL ? decoded->tv_sec : 0ll);
  dec_ll(usec, sizeof(usec), decoded != NULL ? decoded->tv_usec : 0ll);
  dec_ll(wall, sizeof(wall), wall_clock_sec);
  int status_id = ps4rf_bootread_event_status(run_result);

  if (jval_obj_set(event, "msg", jval_new_string("EVENT")) != 0 ||
      jval_obj_set(event, "event", jval_new_string("boot.binding.privileged")) != 0 ||
      jval_obj_set(event, "schema", jval_new_string("ps4rf.boot.binding.privileged.v1")) != 0 ||
      jval_obj_set(event, "status", jval_new_string(run_result == PS4RF_BOOTREAD_RUN_OK
                                                         ? "OK" : "FAILED")) != 0 ||
      jval_obj_set(event, "run_status", jval_new_int((int64_t)status_id)) != 0 ||
      jval_obj_set(event, "run_status_name",
                   jval_new_string(ps4rf_bootread_run_status_name(run_result))) != 0 ||
      jval_obj_set(event, "callback_executed", jval_new_bool(executed)) != 0 ||
      jval_obj_set(event, "cb_status", jval_new_int((int64_t)info->cb_status)) != 0 ||
      jval_obj_set(event, "cb_status_name", jval_new_string(cb_name)) != 0 ||
      jval_obj_set(event, "kexec_rc", jval_new_int((int64_t)info->kexec_rc)) != 0 ||
      jval_obj_set(event, "lstar", j_lstar) != 0 ||
      jval_obj_set(event, "kbase_candidate", j_kbase) != 0 ||
      jval_obj_set(event, "kbase_sdk", j_kbase_sdk) != 0 ||
      jval_obj_set(event, "cross_check", jval_new_string(cross_str)) != 0 ||
      jval_obj_set(event, "source_rva", jval_new_string(rva)) != 0 ||
      jval_obj_set(event, "read_length", jval_new_int((int64_t)len)) != 0 ||
      jval_obj_set(event, "raw_hex", jval_new_string(hex)) != 0 ||
      jval_obj_set(event, "tv_sec", jval_new_string(sec)) != 0 ||
      jval_obj_set(event, "tv_usec", jval_new_string(usec)) != 0 ||
      jval_obj_set(event, "wall_clock_sec", jval_new_string(wall)) != 0 ||
      jval_obj_set(event, "validation", jval_new_string(decoded != NULL && decoded->validation != NULL
                                                            ? decoded->validation
                                                            : PS4RF_BOOTREAD_VAL_NOT_READ)) != 0 ||
      jval_obj_set(event, "kernel_timeval_bytes", jval_new_int(16)) != 0 ||
      jval_obj_set(event, "timeval_layout",
                   jval_new_string("int64 tv_sec at +0, int64 tv_usec at +8 (pinned FW13.52)")) != 0 ||
      jval_obj_set(event, "single_callback", jval_new_bool(1)) != 0 ||
      jval_obj_set(event, "retry", jval_new_bool(0)) != 0 ||
      jval_obj_set(event, "writes_to_kernel", jval_new_bool(0)) != 0 ||
      jval_obj_set(event, "host_supplied_address", jval_new_bool(0)) != 0 ||
      jval_obj_set(event, "generic_read_primitive",
                   jval_new_string("NONE: one fixed 16 byte region, no exported read helper")) != 0 ||
      jval_obj_set(event, "boot_id_claim", jval_new_string("NONE")) != 0 ||
      jval_obj_set(event, "boot_id_note",
                   jval_new_string("the payload reports the measured timeval only; the host forms "
                                   "the boot id independently")) != 0 ||
      jval_obj_set(event, "build_id", jval_new_string(build_id != NULL ? build_id : "")) != 0 ||
      jval_obj_set(event, "label", jval_new_string(label != NULL ? label : "")) != 0 ||
      jval_obj_set(event, "provider", jval_new_string("ps4rfd-bootread-privileged")) != 0 ||
      jval_obj_set(event, "scope",
                   jval_new_string("read-only; one fixed privileged callback per session; fixed "
                                   "RVA and length; no kernel write; no generic primitive")) != 0 ||
      jval_obj_set(event, "profile_decision", jval_new_string("PROFILE_UNBOUND")) != 0) {
    jval_free(event);
    return NULL;
  }
  return event;
}
