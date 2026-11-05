/* PS4RF W9 - read-only kernel attestation implementation.
 *
 * Section discipline (enforced by the build gates, not by comments):
 *   kernel section : ps4rf_attest_kpayload, ps4rf_attest_k_*  (rdmsr + bounded kernel reads)
 *   user section   : ps4rf_attest_run, ps4rf_attest_validate_result (kexec + validation)
 *
 * There is no indirect call anywhere in this file, no allocation, no retry loop and no
 * kernel write. The callback performs at most PS4RF_ATTEST_ENTRY_COUNT byte-window reads at
 * compile-time RVAs relative to the LSTAR-derived base, and it stops at the first failed
 * gate instead of continuing.
 */

#include "ps4rf_attest.h"
#include "ps4rf_libc.h"

/* Both come from libPS4 on the console (payload_utils.h declares them): kexec() is the single
 * privileged transition, get_kernel_base() is the SDK's own LSTAR-based image base, which is
 * what the callback result is cross-checked against. A host build links stand-ins instead. */
extern int kexec(void *func, void *user_arg);
extern uint64_t get_kernel_base(void);

#define PS4RF_XFAST_SYSCALL_RVA 0x1C0u          /* SDK fw_defines.h: K1352_XFAST_SYSCALL */
#define PS4RF_KERNEL_MIN 0xffff800000000000ull  /* canonical kernel range (proven payload) */
#define PS4RF_STATIC_BASE 0xFFFFFFFFD00D0000ull /* base the pinned image is relocated for */

/* ------------------------------------------------------------------ kernel section */

/* The two leaf operations of the measurement are separate (weak, not inlined) functions: the
 * offline harness links its own definitions to drive the *production* callback path against a
 * synthetic image, while a shipped artefact uses these. Exactly one rdmsr lives here. */
__attribute__((weak, noinline)) uint64_t ps4rf_attest_k_readmsr(uint32_t reg) {
  uint32_t low = 0, high = 0;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(reg));
  return ((uint64_t)high << 32) | (uint64_t)low;
}

__attribute__((weak, noinline)) uint8_t ps4rf_attest_k_read8(uint64_t base, uint32_t rva) {
  return *(volatile uint8_t *)(base + (uint64_t)rva);
}

int ps4rf_attest_k_lstar_ok(uint64_t lstar) {
  if (lstar < PS4RF_KERNEL_MIN) return 0;
  /* LSTAR must point at the syscall entry: page offset equals the SDK's xfast RVA */
  if ((lstar & 0xfffull) != PS4RF_XFAST_SYSCALL_RVA) return 0;
  return 1;
}

int ps4rf_attest_k_pointer_ok(uint64_t value) {
  return value >= PS4RF_KERNEL_MIN;
}

uint64_t ps4rf_attest_k_expected_u64(const uint8_t *expected, uint64_t slide, uint32_t kind) {
  uint64_t v = 0;
  for (uint32_t i = 0; i < 8u; i++) v |= ((uint64_t)expected[i]) << (8u * i);
  if (kind == PS4RF_ATTEST_KIND_RELOCATED) v += slide;
  return v;
}

static void ps4rf_attest_k_copy(uint8_t *dst, const uint8_t *src, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) dst[i] = src[i];
}

int ps4rf_attest_kpayload(void *td, struct ps4rf_attest_args *args) {
  (void)td;
  if (args == 0) return -1;
  ps4rf_attest_info *info = args->info;
  if (info == 0) return -1;
  if (info->magic_in != PS4RF_ATTEST_MAGIC_IN) {
    info->cb_status = PS4RF_ATTEST_CB_MAGIC;
    return -1;
  }

  /* the one privileged instruction, and only the observed value is reported */
  uint64_t lstar = ps4rf_attest_k_readmsr(0xC0000082u);
  info->lstar = lstar;
  if (!ps4rf_attest_k_lstar_ok(lstar)) {
    info->cb_status = PS4RF_ATTEST_CB_LSTAR_SHAPE;
    return 0;                       /* nothing else is read */
  }
  uint64_t kbase = lstar - (uint64_t)PS4RF_XFAST_SYSCALL_RVA;
  info->kbase_lstar = kbase;
  uint64_t slide = kbase - PS4RF_STATIC_BASE;
  info->slide = slide;

  info->entry_count = PS4RF_ATTEST_ENTRY_COUNT;
  info->strict_matches = 0u;
  info->strict_mismatches = 0u;
  info->structural_observations = 0u;
  info->read_count = 0u;
  info->cb_status = PS4RF_ATTEST_CB_OK;

  for (uint32_t e = 0; e < PS4RF_ATTEST_ENTRY_COUNT; e++) {
    const ps4rf_attest_entry *row = &PS4RF_ATTEST_TABLE[e];
    uint8_t observed[PS4RF_ATTEST_MAX_LEN];
    for (uint32_t i = 0; i < PS4RF_ATTEST_MAX_LEN; i++) observed[i] = 0u;

    /* bounded, fixed-window read: first entry is the image identity and gates the rest */
    for (uint32_t i = 0; i < row->len; i++) {
      observed[i] = ps4rf_attest_k_read8(kbase, row->rva + i);
    }
    info->read_count += 1u;
    ps4rf_attest_k_copy(info->entries[e].observed, observed, row->len);
    info->entries[e].observed_len = row->len;

    if (row->policy == PS4RF_ATTEST_POLICY_STRUCTURAL_ONLY) {
      /* Measured and reported. Never part of the strict score, never stops the attestation. */
      uint64_t value = 0;
      for (uint32_t i = 0; i < row->len && i < 8u; i++) {
        value |= ((uint64_t)observed[i]) << (8u * i);
      }
      info->aperture = value;
      int in_range = ps4rf_attest_k_pointer_ok(value) && ((value & 0xfull) == 0ull);
      info->entries[e].status = in_range ? PS4RF_ATTEST_ENTRY_STRUCT_OK
                                         : PS4RF_ATTEST_ENTRY_STRUCT_BAD;
      info->structural_observations += 1u;
      continue;
    }

    int match;
    if (row->kind == PS4RF_ATTEST_KIND_RELOCATED) {
      /* 8 byte pointer: the image value plus the slide must equal the live value */
      uint64_t got = 0;
      for (uint32_t i = 0; i < 8u; i++) got |= ((uint64_t)observed[i]) << (8u * i);
      uint64_t expected = ps4rf_attest_k_expected_u64(row->expected, slide, row->kind);
      match = (row->len == 8u) && (expected == got);
    } else {
      /* byte-exact window compare (lengths above 8 are handled here, not by a u64 read) */
      match = 1;
      for (uint32_t i = 0; i < row->len; i++) {
        if (observed[i] != row->expected[i]) { match = 0; break; }
      }
    }
    info->entries[e].status = match ? PS4RF_ATTEST_ENTRY_MATCH : PS4RF_ATTEST_ENTRY_MISMATCH;
    if (match) {
      info->strict_matches += 1u;
    } else {
      info->strict_mismatches += 1u;   /* fail closed: the run is stopped by the caller */
      if (e == 0u) {                   /* image identity failed: stop, read nothing else */
        info->cb_status = PS4RF_ATTEST_CB_IMAGE;
        break;
      }
    }
  }

  info->magic_out = PS4RF_ATTEST_MAGIC_OUT;
  info->guard = PS4RF_ATTEST_GUARD;
  return 0;
}

/* -------------------------------------------------------------------- user section */

static int g_ps4rf_attest_called = 0;

int ps4rf_attest_run(ps4rf_attest_info *info) {
  if (info == 0) return PS4RF_ATTEST_RUN_RESULT_INVALID;
  if (g_ps4rf_attest_called) return PS4RF_ATTEST_RUN_ALREADY;   /* single shot, no retry */
  g_ps4rf_attest_called = 1;

  uint32_t i;
  uint8_t *raw = (uint8_t *)info;
  for (i = 0; i < sizeof(ps4rf_attest_info); i++) raw[i] = 0u;
  info->magic_in = PS4RF_ATTEST_MAGIC_IN;
  info->kbase_sdk = get_kernel_base();

  int rc = kexec((void *)&ps4rf_attest_kpayload, (void *)info);  /* SDK-identical: info direkt */
  info->kexec_rc = (int32_t)rc;

  int verdict = ps4rf_attest_validate_result(info);
  if (verdict != PS4RF_ATTEST_RUN_OK) return verdict;
  if (rc != 0) return PS4RF_ATTEST_RUN_KEXEC_FAILED;
  return PS4RF_ATTEST_RUN_OK;
}

int ps4rf_attest_validate_result(const ps4rf_attest_info *info) {
  if (info == 0) return PS4RF_ATTEST_RUN_RESULT_INVALID;
  /* A callback that reported a status ran; that status is the answer, even when it stopped
   * before the end of the block (no magic_out: nothing was measured). */
  if (info->cb_status != PS4RF_ATTEST_CB_OK) return PS4RF_ATTEST_RUN_CALLBACK;
  if (info->magic_out != PS4RF_ATTEST_MAGIC_OUT) return PS4RF_ATTEST_RUN_RESULT_INVALID;
  if (info->guard != PS4RF_ATTEST_GUARD) return PS4RF_ATTEST_RUN_RESULT_INVALID;
  if (info->entry_count != PS4RF_ATTEST_ENTRY_COUNT) return PS4RF_ATTEST_RUN_RESULT_INVALID;
  /* A failed STRICT_FINGERPRINT is a stop, not a note (fail closed). STRUCTURAL_ONLY
   * observations deliberately do not appear in this test. */
  if (info->strict_mismatches != 0u) return PS4RF_ATTEST_RUN_CALLBACK;
  if (info->strict_matches + info->strict_mismatches + info->structural_observations !=
      PS4RF_ATTEST_ENTRY_COUNT)
    return PS4RF_ATTEST_RUN_RESULT_INVALID;
  if (info->read_count == 0u || info->read_count > PS4RF_ATTEST_ENTRY_COUNT)
    return PS4RF_ATTEST_RUN_RESULT_INVALID;
  if (info->lstar == 0ull || info->kbase_lstar == 0ull)
    return PS4RF_ATTEST_RUN_RESULT_INVALID;
  if (info->kbase_sdk == 0ull) return PS4RF_ATTEST_RUN_RESULT_INVALID;
  /* the LSTAR -> base relation itself is reported as data (observed values plus the SDK
   * constant); it is not re-derived here, so no kernel RVA constant lives in the user section */
  return PS4RF_ATTEST_RUN_OK;
}

/* ---------------------------------------------------------------- report (user section) */

const char *ps4rf_attest_cb_status_name(uint32_t status) {
  if (status == PS4RF_ATTEST_CB_OK) return "OK";
  if (status == PS4RF_ATTEST_CB_ARGS) return "ARGS_MISSING";
  if (status == PS4RF_ATTEST_CB_MAGIC) return "CALLER_MARKER_MISSING";
  if (status == PS4RF_ATTEST_CB_LSTAR_SHAPE) return "LSTAR_SHAPE_INVALID";
  if (status == PS4RF_ATTEST_CB_IMAGE) return "IMAGE_IDENTITY_MISMATCH";
  return "UNKNOWN";
}

const char *ps4rf_attest_entry_status_name(uint32_t status) {
  if (status == PS4RF_ATTEST_ENTRY_MATCH) return "MATCH";
  if (status == PS4RF_ATTEST_ENTRY_MISMATCH) return "MISMATCH";
  if (status == PS4RF_ATTEST_ENTRY_STRUCT_OK) return "STRUCT_OK";
  if (status == PS4RF_ATTEST_ENTRY_STRUCT_BAD) return "STRUCT_BAD";
  return "NOT_READ";
}

static void u64_hex(char *out, uint64_t v) {
  static const char digits[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  out[0] = '0';
  out[1] = 'x';
  for (uint32_t i = 0; i < 16u; i++) {
    out[2u + i] = digits[(v >> (4u * (15u - i))) & 0xfull];
  }
  out[18] = '\0';
}

jval *ps4rf_attest_event(const ps4rf_attest_info *info, int run_status,
                         const char *build_id, const char *label) {
  if (info == NULL) return NULL;
  jval *event = jval_new_object();
  jval *entries = jval_new_array();
  char buf[64];
  if (event == NULL || entries == NULL) {
    jval_free(event);
    jval_free(entries);
    return NULL;
  }

  int executed = info->magic_out == PS4RF_ATTEST_MAGIC_OUT;
  uint32_t strict_total = 0u;
  for (uint32_t e = 0; e < PS4RF_ATTEST_ENTRY_COUNT; e++) {
    if (PS4RF_ATTEST_TABLE[e].policy == PS4RF_ATTEST_POLICY_STRICT_FINGERPRINT) strict_total++;
  }
  /* STRUCTURAL_ONLY observations are intentionally absent from this verdict. */
  int ok = executed && run_status == PS4RF_ATTEST_RUN_OK &&
           info->cb_status == PS4RF_ATTEST_CB_OK && info->strict_mismatches == 0u;

  u64_hex(buf, info->lstar);
  jval *j_lstar = jval_new_string(buf);
  u64_hex(buf, info->kbase_lstar);
  jval *j_kbase = jval_new_string(buf);
  u64_hex(buf, info->kbase_sdk);
  jval *j_kbase_sdk = jval_new_string(buf);
  u64_hex(buf, info->slide);
  jval *j_slide = jval_new_string(buf);
  u64_hex(buf, info->aperture);
  jval *j_aperture = jval_new_string(buf);

  if (jval_obj_set(event, "msg", jval_new_string("EVENT")) != 0 ||
      jval_obj_set(event, "event", jval_new_string("kernel.attestation")) != 0 ||
      jval_obj_set(event, "status", jval_new_string(ok ? "OK" : "FAILED")) != 0 ||
      jval_obj_set(event, "callback_executed", jval_new_bool(executed)) != 0 ||
      jval_obj_set(event, "execution_note",
                   jval_new_string(executed
                                       ? "callback ran; results below are measured"
                                       : "callback did not run: no measurement was taken, "
                                         "per-entry results are deliberately omitted")) != 0 ||
      jval_obj_set(event, "run_status", jval_new_int((int64_t)run_status)) != 0 ||
      jval_obj_set(event, "cb_status", jval_new_int((int64_t)info->cb_status)) != 0 ||
      jval_obj_set(event, "cb_status_name",
                   jval_new_string(ps4rf_attest_cb_status_name(info->cb_status))) != 0 ||
      jval_obj_set(event, "kexec_rc", jval_new_int((int64_t)info->kexec_rc)) != 0 ||
      jval_obj_set(event, "copyout_rc", jval_new_null()) != 0 ||
      jval_obj_set(event, "copyout_note",
                   jval_new_string("caller buffer write, no kernel copyout helper used")) != 0 ||
      jval_obj_set(event, "lstar", j_lstar) != 0 ||
      jval_obj_set(event, "kbase_candidate", j_kbase) != 0 ||
      jval_obj_set(event, "kbase_sdk", j_kbase_sdk) != 0 ||
      jval_obj_set(event, "kbase_slide", j_slide) != 0 ||
      jval_obj_set(event, "kbase_cross_check",
                   jval_new_string(info->kbase_lstar == info->kbase_sdk ? "MATCH"
                                                                       : "MISMATCH")) != 0 ||
      jval_obj_set(event, "aperture_global", j_aperture) != 0 ||
      jval_obj_set(event, "entry_count", jval_new_int((int64_t)info->entry_count)) != 0 ||
      jval_obj_set(event, "read_count", jval_new_int((int64_t)info->read_count)) != 0 ||
      jval_obj_set(event, "strict_matches", jval_new_int((int64_t)info->strict_matches)) != 0 ||
      jval_obj_set(event, "strict_total", jval_new_int((int64_t)strict_total)) != 0 ||
      jval_obj_set(event, "strict_mismatches",
                   jval_new_int((int64_t)info->strict_mismatches)) != 0 ||
      jval_obj_set(event, "structural_observations",
                   jval_new_int((int64_t)info->structural_observations)) != 0 ||
      jval_obj_set(event, "structural_note",
                   jval_new_string("STRUCTURAL_ONLY: measured and reported, never part of the "
                                   "strict score, never on its own a failure")) != 0 ||
      jval_obj_set(event, "build_id", jval_new_string(build_id != NULL ? build_id : "")) != 0 ||
      jval_obj_set(event, "label", jval_new_string(label != NULL ? label : "")) != 0 ||
      jval_obj_set(event, "provider", jval_new_string("ps4rfd-attestation-fixed")) != 0 ||
      jval_obj_set(event, "scope",
                   jval_new_string("read-only; one callback per session; no host supplied "
                                   "address; no kernel write")) != 0 ||
      jval_obj_set(event, "profile_decision", jval_new_string("PROFILE_UNBOUND")) != 0 ||
      jval_obj_set(event, "boot_binding", jval_new_string("BOOT_ID_UNVERIFIED")) != 0) {
    jval_free(event);
    return NULL;
  }

  /* A callback that never ran reports no results at all: an optimistic per-entry status built
   * from a zeroed struct would be a claim nobody measured. The host recomputes everything and
   * the failure is carried by kexec_rc / run_status instead. */
  for (uint32_t e = 0; executed && e < PS4RF_ATTEST_ENTRY_COUNT && e < PS4RF_ATTEST_ENTRY_MAX;
       e++) {
    jval *row = jval_new_object();
    char hex[2u * PS4RF_ATTEST_MAX_LEN + 1u];
    uint32_t len = info->entries[e].observed_len;
    if (row == NULL) { jval_free(event); return NULL; }
    if (len > PS4RF_ATTEST_MAX_LEN) len = PS4RF_ATTEST_MAX_LEN;
    ps4rf_hex_encode(info->entries[e].observed, len, hex);
    int strict = PS4RF_ATTEST_TABLE[e].policy == PS4RF_ATTEST_POLICY_STRICT_FINGERPRINT;
    if (jval_obj_set(row, "id", jval_new_string(PS4RF_ATTEST_TABLE[e].id)) != 0 ||
        jval_obj_set(row, "policy", jval_new_string(strict ? "STRICT_FINGERPRINT"
                                                          : "STRUCTURAL_ONLY")) != 0 ||
        jval_obj_set(row, "exact_match_claim", jval_new_bool(strict)) != 0 ||
        jval_obj_set(row, "rva_len", jval_new_int((int64_t)PS4RF_ATTEST_TABLE[e].len)) != 0 ||
        jval_obj_set(row, "status",
                     jval_new_string(ps4rf_attest_entry_status_name(
                         info->entries[e].status))) != 0 ||
        jval_obj_set(row, "observed", jval_new_string(hex)) != 0) {
      jval_free(row);
      jval_free(event);
      return NULL;
    }
    if (jval_arr_add(entries, row) != 0) { jval_free(event); return NULL; }
  }
  if (jval_obj_set(event, "entries", entries) != 0) {
    jval_free(event);
    return NULL;
  }
  return event;
}
