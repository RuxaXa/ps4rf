/* PS4RF W12 -- one bounded kernel.read provider callback: implementation.
 *
 * Section discipline (enforced by the build gates, not by comments):
 *   kernel section : ps4rf_kread_kpayload, ps4rf_kread_k_*  (one rdmsr, the bounded copy)
 *   user section   : ps4rf_kread_run / _validate / the event builder (kexec once)
 *
 * The host input is exactly (region index, offset, length) -- three integers, never an address and
 * never an rva: the index names a row of the generated compile-time region table and the address
 * is composed inside the callback from the W9/W11.2-proven kbase relation plus that row's rva.
 * There is no indirect call anywhere in this file, no allocation, no retry loop, no loop over
 * addresses, no kernel write. The callback copies exactly the requested bytes
 * (PS4RF_KREAD_MAX_LEN, from the generated header) of the
 * one selected region into the payload's own result block and nothing else.
 */

#include "ps4rf_kread.h"
#include "ps4rf_kread_regions.h"
#include "ps4rf_libc.h"
#ifdef PS4RF_TARGET_PS4
/* W15R2: the console build's wall clock hook, used only to refuse a boot instant that lies in the
 * future. The offline harnesses link this module without a platform, and the AUTHORITATIVE future
 * check is the host's (tools/profiles/bootid.py), so the dependency is the console build's only. */
#include "ps4rf_platform.h"
#endif
#include "sha256.h"

/* The result block is a fixed, bounded layout: this assertion is what keeps it that way, and
 * the manifest gate derives the same numbers from the built image. */
typedef char ps4rf_kread_info_is_4256[(sizeof(ps4rf_kread_info) == 4256) ? 1 : -1];

/* Both come from libPS4 on the console: kexec() is the single privileged transition, and
 * get_kernel_base() is the SDK's own LSTAR-based image base, which is what the callback
 * cross-checks its LSTAR-derived candidate against before reading anything. A host build links
 * honest stand-ins (ps4rf_kread_host.c) or the offline simulator (tests/harness). */
extern int kexec(void *func, void *user_arg);
extern uint64_t get_kernel_base(void);

#define PS4RF_KREAD_XFAST_RVA 0x1C0u                  /* SDK fw_defines K1352_XFAST_SYSCALL  */
#define PS4RF_KREAD_KERNEL_MIN 0xffff800000000000ull
#define PS4RF_KREAD_LSTAR_MSR 0xC0000082u

/* ------------------------------------------------------------------ kernel section */

/* The two leaf operations are separate (weak, not inlined) functions: the offline harness links
 * its own definitions to drive the *production* callback path against a synthetic image, while a
 * shipped artefact uses these. Exactly one rdmsr lives in the whole payload. */
__attribute__((weak, noinline)) uint64_t ps4rf_kread_k_readmsr(uint32_t reg) {
  uint32_t low = 0, high = 0;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(reg));
  return ((uint64_t)high << 32) | (uint64_t)low;
}

__attribute__((weak, noinline)) uint8_t ps4rf_kread_k_read8(uint64_t base, uint32_t rva) {
  return *(volatile uint8_t *)(base + (uint64_t)rva);
}

int ps4rf_kread_k_lstar_ok(uint64_t lstar) {
  if (lstar < PS4RF_KREAD_KERNEL_MIN) return 0;
  /* LSTAR must point at the syscall entry: page offset equals the SDK's xfast RVA */
  if ((lstar & 0xfffull) != PS4RF_KREAD_XFAST_RVA) return 0;
  return 1;
}

int ps4rf_kread_kpayload(void *td, struct ps4rf_kread_args *args) {
  (void)td;
  if (args == 0) return -1;
  ps4rf_kread_info *info = args->info;          /* wrapper field 2 (offset 8): never field 1 */
  if (info == 0) return -1;
  /* An unauthenticated block is the only reason the callback could hold a pointer it does not
   * own (the kernel's syscall handler): it writes nothing on that path -- not even a status
   * word -- and reports by returning. The user section turns the untouched block into
   * RESULT_INVALID. */
  if (info->magic_in != PS4RF_KREAD_MAGIC_IN) return -1;
  info->magic_out = PS4RF_KREAD_MAGIC_OUT;      /* the callback body has started            */
  info->flags = (PS4RF_KREAD_FLAG_SINGLE_CALLBACK | PS4RF_KREAD_FLAG_NO_RETRY |
                 PS4RF_KREAD_FLAG_NO_KERNEL_WRITE | PS4RF_KREAD_FLAG_NO_HOST_ADDRESS);

  /* 1. request bounds, before anything privileged: an invalid request performs no rdmsr and
   *    reads no byte. The host supplies an index, an offset and a length -- never an address. */
  uint32_t index = info->region_index;
  uint32_t offset = info->offset;
  uint32_t length = info->length;
  if (index >= PS4RF_KREAD_REGION_COUNT) {
    info->cb_status = PS4RF_KREAD_CB_REGION;
    return 0;
  }
  if (length == 0u || length > PS4RF_KREAD_MAX_LEN) {
    info->cb_status = PS4RF_KREAD_CB_LENGTH;
    return 0;
  }
  const ps4rf_kread_region *region = &PS4RF_KREAD_REGIONS[index];
  uint32_t sum = offset + length;               /* the checked add (32 bit)                  */
  if (sum < offset) {                           /* wraparound refused                        */
    info->cb_status = PS4RF_KREAD_CB_OVERFLOW;
    return 0;
  }
  if (sum > region->length) {                   /* region containment: cross-region refused  */
    info->cb_status = PS4RF_KREAD_CB_CONTAINMENT;
    return 0;
  }
  uint64_t rva64 = (uint64_t)region->rva + (uint64_t)offset;
  if (rva64 > 0xFFFFFFFFull) {                  /* rva composition wraparound refused        */
    info->cb_status = PS4RF_KREAD_CB_OVERFLOW;
    return 0;
  }
  info->region_rva = (uint64_t)region->rva;
  info->resolved_rva = rva64;
  info->offset_length_sum = (uint64_t)sum;

  /* 2. base: the one privileged instruction, then the shape gate and the SDK cross check,
   *    both before a single byte is read (the W11.2 shape). */
  uint64_t lstar = ps4rf_kread_k_readmsr(PS4RF_KREAD_LSTAR_MSR);
  info->lstar = lstar;
  if (!ps4rf_kread_k_lstar_ok(lstar)) {
    info->cb_status = PS4RF_KREAD_CB_LSTAR_SHAPE;
    return 0;                                   /* zero bytes read                           */
  }
  uint64_t kbase = lstar - (uint64_t)PS4RF_KREAD_XFAST_RVA;
  info->kbase_candidate = kbase;
  if (info->kbase_sdk == 0ull || info->kbase_sdk != kbase) {
    info->cross_check = 0ull;
    info->cb_status = PS4RF_KREAD_CB_KBASE_MISMATCH;
    return 0;                                   /* zero bytes read                           */
  }
  info->cross_check = 1ull;

  /* 3. the resolved runtime VA: checked add, canonical, no wraparound. EVIDENCE ONLY: it is
   *    written here and later read by validate()/the event; it is never an input and is never
   *    read back into an address. */
  uint64_t address = kbase + rva64;
  if (address < kbase || address < PS4RF_KREAD_KERNEL_MIN) {
    info->cb_status = PS4RF_KREAD_CB_ADDRESS;
    return 0;
  }
  info->resolved_runtime_va = address;

  /* 4. the bounded copy: exactly `length` bytes (1..PS4RF_KREAD_MAX_LEN) from the one
   *    the payload's own result block. No other store in this callback, no kernel write. */
  uint32_t rva32 = (uint32_t)rva64;
  for (uint32_t i = 0u; i < length; i++) {
    info->bytes[i] = ps4rf_kread_k_read8(kbase, rva32 + i);
  }
  info->copied_len = length;
  info->sha256_status = PS4RF_KREAD_SHA_NOT_MEASURED;  /* measured by the user section      */
  info->cb_status = PS4RF_KREAD_CB_OK;

  /* 5. return: no further kernel memory operation */
  info->guard = PS4RF_KREAD_GUARD;
  return 0;
}

/* -------------------------------------------------------------------- user section */

/* W14: the one shot is per SESSION, not per payload lifetime. The resident agent serves many
 * authenticated sessions per boot; the authorization is not persistent (one release record per
 * read), so the structural guard must be re-armed exactly once per session -- and only where a
 * session begins, never from a request. A session can therefore still perform at most one
 * privileged transition, which is what the guard was for; the reset itself is not request
 * driven and not reachable from any handler. */

static int g_ps4rf_kread_called = 0;         /* one shot: set before kexec, reset per session */

void ps4rf_kread_session_begin(ps4rf_kread_info *info)
{
    g_ps4rf_kread_called = 0;
    if (info != NULL) {
        memset(info, 0, sizeof(*info));
        info->magic_in = PS4RF_KREAD_MAGIC_IN;
    }
}


int ps4rf_kread_run(ps4rf_kread_info *info, uint32_t region_index, uint32_t offset,
                    uint32_t length) {
  if (info == 0) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (g_ps4rf_kread_called) return PS4RF_KREAD_RUN_ALREADY;
  g_ps4rf_kread_called = 1;                  /* the guard is set BEFORE any block write   */

  uint8_t *raw = (uint8_t *)info;
  for (uint32_t i = 0u; i < sizeof(ps4rf_kread_info); i++) raw[i] = 0u;
  info->magic_in = PS4RF_KREAD_MAGIC_IN;
  info->region_index = region_index;
  info->offset = offset;
  info->length = length;

  /* The user section refuses an out-of-bounds request before the privileged transition, so an
   * invalid request never reaches kexec; the callback re-checks everything (it decides no
   * authority on its own). */
  if (region_index >= PS4RF_KREAD_REGION_COUNT) {
    info->cb_status = PS4RF_KREAD_CB_NOT_RUN;
    info->run_status = PS4RF_KREAD_RUN_REGION_INDEX_INVALID;
    return PS4RF_KREAD_RUN_REGION_INDEX_INVALID;
  }
  /* a row whose identity is neither fingerprintable nor structural is not a region this table may
   * serve: refused exactly like a missing row. The generator already refuses to compile an
   * UNRESOLVED entry, so this is the payload's own structural guard against a future table. */
  if (PS4RF_KREAD_REGIONS[region_index].identity_status != PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT &&
      PS4RF_KREAD_REGIONS[region_index].identity_status != PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY) {
    info->cb_status = PS4RF_KREAD_CB_NOT_RUN;
    info->run_status = PS4RF_KREAD_RUN_REGION_INDEX_INVALID;
    return PS4RF_KREAD_RUN_REGION_INDEX_INVALID;
  }
  if (length == 0u || length > PS4RF_KREAD_MAX_LEN) {
    info->cb_status = PS4RF_KREAD_CB_NOT_RUN;
    info->run_status = PS4RF_KREAD_RUN_REQUEST_INVALID;
    return PS4RF_KREAD_RUN_REQUEST_INVALID;
  }
  uint32_t sum = offset + length;
  if (sum < offset || sum > PS4RF_KREAD_REGIONS[region_index].length) {
    info->cb_status = PS4RF_KREAD_CB_NOT_RUN;
    info->run_status = PS4RF_KREAD_RUN_REQUEST_INVALID;
    return PS4RF_KREAD_RUN_REQUEST_INVALID;
  }

  info->kbase_sdk = get_kernel_base();

  /* the payload is entered with the caller's block in the wrapper's second field; the payload
   * itself passes the info block, the SDK builds the wrapper around it */
  int rc = kexec((void *)&ps4rf_kread_kpayload, (void *)info);
  info->kexec_rc = (int32_t)rc;

  int verdict = ps4rf_kread_validate(info);
  if (verdict != PS4RF_KREAD_RUN_OK) {
    info->run_status = verdict;
    return verdict;
  }
  if (rc != 0) {
    info->run_status = PS4RF_KREAD_RUN_KEXEC_FAILED;
    return PS4RF_KREAD_RUN_KEXEC_FAILED;
  }

  /* The SHA-256 of the copied bytes is measured here, after the single callback returned --
   * never inside the callback (the kernel section has no call target beyond its own leaves),
   * over exactly the bytes the callback copied into this block. */
  ps4rf_sha256(info->bytes, (size_t)info->copied_len, info->sha256);
  info->sha256_status = PS4RF_KREAD_SHA_MEASURED;
  info->run_status = PS4RF_KREAD_RUN_OK;
  return PS4RF_KREAD_RUN_OK;
}

int ps4rf_kread_validate(const ps4rf_kread_info *info) {
  if (info == 0) return PS4RF_KREAD_RUN_RESULT_INVALID;
  /* A callback that reported a status ran; that status is the answer, even when it stopped
   * before reading (no magic_out: nothing was measured). */
  if (info->cb_status != PS4RF_KREAD_CB_OK) return PS4RF_KREAD_RUN_CALLBACK;
  if (info->magic_out != PS4RF_KREAD_MAGIC_OUT) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->guard != PS4RF_KREAD_GUARD) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->length == 0u || info->length > PS4RF_KREAD_MAX_LEN) {
    return PS4RF_KREAD_RUN_RESULT_INVALID;
  }
  if (info->copied_len != info->length) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->region_index >= PS4RF_KREAD_REGION_COUNT) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->region_rva != (uint64_t)PS4RF_KREAD_REGIONS[info->region_index].rva) {
    return PS4RF_KREAD_RUN_RESULT_INVALID;
  }
  if (info->offset_length_sum != (uint64_t)(info->offset + info->length)) {
    return PS4RF_KREAD_RUN_RESULT_INVALID;
  }
  if (info->resolved_rva != info->region_rva + (uint64_t)info->offset) {
    return PS4RF_KREAD_RUN_RESULT_INVALID;
  }
  if (info->resolved_runtime_va != info->kbase_candidate + info->resolved_rva) {
    return PS4RF_KREAD_RUN_RESULT_INVALID;
  }
  if (info->resolved_runtime_va < PS4RF_KREAD_KERNEL_MIN) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->cross_check != 1ull) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->lstar == 0ull || info->kbase_candidate == 0ull) return PS4RF_KREAD_RUN_RESULT_INVALID;
  if (info->kbase_sdk == 0ull) return PS4RF_KREAD_RUN_RESULT_INVALID;
  return PS4RF_KREAD_RUN_OK;
}

/* W13-C2: the trigger reads its three integers from body.arguments (wire catalog revision R2) and
 * hands them to ps4rf_kread_run(), which owns every bound: the index must name a row of
 * PS4RF_KREAD_REGIONS, the length must be 1..PS4RF_KREAD_MAX_LEN and offset + length must stay
 * inside that row. A request that cannot be parsed is refused explicitly -- ARGUMENTS_INVALID,
 * before every bound rule and before any kexec -- and must never be handed to the run path with
 * substitute values. There is no default region, no probe and no second read path. */
/* The explicit refusal of a request the parser could not read. It writes a zeroed block with the
 * NOT_RUN callback status and the ARGUMENTS_INVALID verdict, and it deliberately does not touch the
 * one-shot guard: a malformed request is not a read attempt, so it must not consume the single
 * read this payload is allowed to perform. */
int ps4rf_kread_refuse_arguments(ps4rf_kread_info *info) {
  if (info == 0) return PS4RF_KREAD_RUN_RESULT_INVALID;
  uint8_t *raw = (uint8_t *)info;
  for (uint32_t i = 0u; i < sizeof(ps4rf_kread_info); i++) raw[i] = 0u;
  info->magic_in = PS4RF_KREAD_MAGIC_IN;
  info->cb_status = PS4RF_KREAD_CB_NOT_RUN;
  info->run_status = PS4RF_KREAD_RUN_ARGUMENTS_INVALID;
  return PS4RF_KREAD_RUN_ARGUMENTS_INVALID;
}

/* ---- W15R2 -- the lifetime boot binding: ONE fixed step per agent lifetime, not a request ----
 *
 * Why a fixed step: on this firmware the boot instant is not readable through the userland sysctl
 * wrappers at all (W11.1 live: sysctlbyname("kern.boottime") and the MIB path both delivered zero
 * bytes -- BOOT_SYSCTL_NAME_NOT_FOUND / BOOT_SYSCTL_MIB_NOT_FOUND). The only source that has ever
 * produced the value on the console is the bounded read of the compiled `boottime` row (W11.2
 * live: RVA 0x224C6C8, tv_sec 1791179388 / tv_usec 549567 -> BOOT-f0329415c5d8517d, re-derived on
 * the host). The resident daemon therefore measures it exactly once at bootstrap through the SAME
 * single privileged callback the research read uses, and every session of the lifetime announces
 * the cached value.
 *
 * Rules that hold unchanged: the row index is a compile-time constant of the generated table (no
 * request field, no host value), there is no address anywhere, the read is bounded by the row and
 * the callback is entered through the one kexec call site inside ps4rf_kread_run() -- no second
 * call site, no retry, no event of its own.
 *
 * The payload refuses only values that cannot be a boot instant. The AUTHORITATIVE validation of
 * the binding stays host side (tools/profiles/bootid.py: floor, usec range, the console wall
 * clock, host skew, profile binding); a value this function refuses is never reported as measured.
 */
#define PS4RF_KREAD_BOOTTIME_ROW PS4RF_KREAD_REGION_IDX_BOOTTIME
#define PS4RF_KREAD_BOOTTIME_LEN 16u
#define PS4RF_KREAD_BOOTTIME_MIN_SEC 1000000000ll    /* 2001-09-09: the host floor (bootid.py) */
#define PS4RF_KREAD_BOOTTIME_USEC_LIMIT 1000000ll

static long long kread_le_i64(const uint8_t *p) {
  uint64_t v = 0ull;
  unsigned i;
  for (i = 0u; i < 8u; i++) v |= (uint64_t)p[i] << (8u * i);
  return (long long)v;
}

/* The row is addressed by the compile-time index AND its name is verified: a table whose order
 * ever changed must not silently hand the binding another window. */
static int kread_boot_row_ok(void) {
  const ps4rf_kread_region *row = &PS4RF_KREAD_REGIONS[PS4RF_KREAD_BOOTTIME_ROW];
  static const char want[9] = { 'b', 'o', 'o', 't', 't', 'i', 'm', 'e', '\0' };
  unsigned i;
  if (row->length != PS4RF_KREAD_BOOTTIME_LEN) return 0;
  for (i = 0u; i < sizeof(want); i++) {
    if (row->name[i] != want[i]) return 0;
  }
  return 1;
}

/* W15R3: the lifetime's boot-binding verdict (see ps4rf_kread.h). It is written by the one fixed
 * measurement only and is read by the privileged provider; the read path neither sets nor clears
 * it. 0 is the fail-closed value: a lifetime that never measured, or measured and failed, has no
 * established binding. */
static int g_boot_established = 0;

int ps4rf_kread_boot_established(void) {
  return g_boot_established != 0;
}

void ps4rf_kread_boot_record_platform(void) {
  g_boot_established = 1;              /* the lifetime's binding, measured by the platform route */
}

int ps4rf_kread_boot_binding(ps4rf_kread_info *info, long long *sec, long long *usec) {
#ifdef PS4RF_TARGET_PS4
  const ps4rf_platform *pf = ps4rf_platform_get();
  long long wall = 0ll;
#endif
  int run_status;

  g_boot_established = 0;                       /* fail closed until this measurement says OK */
  if (info == 0 || sec == 0 || usec == 0) return PS4RF_KREAD_BOOT_INCOMPLETE;
  *sec = 0ll;
  *usec = 0ll;
  if (!kread_boot_row_ok()) return PS4RF_KREAD_BOOT_ROW;

  ps4rf_kread_session_begin(info);              /* the one shot of this fixed step */
  run_status = ps4rf_kread_run(info, (uint32_t)PS4RF_KREAD_BOOTTIME_ROW, 0u,
                               PS4RF_KREAD_BOOTTIME_LEN);
  if (run_status != PS4RF_KREAD_RUN_OK) return PS4RF_KREAD_BOOT_RUN_FAILED;
  if (info->copied_len != PS4RF_KREAD_BOOTTIME_LEN) return PS4RF_KREAD_BOOT_INCOMPLETE;

  *sec = kread_le_i64(&info->bytes[0]);         /* tv_sec  at +0, little endian */
  *usec = kread_le_i64(&info->bytes[8]);        /* tv_usec at +8, little endian */
  if (*sec <= 0ll) return PS4RF_KREAD_BOOT_SEC;
  if (*usec < 0ll || *usec >= PS4RF_KREAD_BOOTTIME_USEC_LIMIT) return PS4RF_KREAD_BOOT_USEC;
  if (*sec < PS4RF_KREAD_BOOTTIME_MIN_SEC) return PS4RF_KREAD_BOOT_FLOOR;
#ifdef PS4RF_TARGET_PS4
  /* The boot instant cannot lie in the future. The wall clock hook is the same userland source
   * the W11 flow used; where it cannot answer (this firmware), the check is the host's
   * (bootid.py applies the console wall clock and the host skew window). */
  if (pf != 0 && pf->wall_sec != 0 && pf->wall_sec(&wall) == PS4RF_TF_OK && wall > 0ll &&
      *sec > wall) {
    *sec = 0ll;
    *usec = 0ll;
    return PS4RF_KREAD_BOOT_FUTURE;
  }
#endif
  g_boot_established = 1;                       /* the lifetime now has a measured binding */
  return PS4RF_KREAD_BOOT_OK;
}

const char *ps4rf_kread_boot_status_name(int status) {
  if (status == PS4RF_KREAD_BOOT_OK) return "OK";
  if (status == PS4RF_KREAD_BOOT_RUN_FAILED) return "BOOT_READ_FAILED";
  if (status == PS4RF_KREAD_BOOT_INCOMPLETE) return "BOOT_TIMEVAL_INCOMPLETE";
  if (status == PS4RF_KREAD_BOOT_SEC) return "BOOT_SEC_UNINITIALISED";
  if (status == PS4RF_KREAD_BOOT_USEC) return "BOOT_USEC_INVALID";
  if (status == PS4RF_KREAD_BOOT_FLOOR) return "BOOT_TIME_IMPLAUSIBLE";
  if (status == PS4RF_KREAD_BOOT_FUTURE) return "BOOT_TIME_IN_FUTURE";
  if (status == PS4RF_KREAD_BOOT_ROW) return "BOOT_REGION_ROW_MISSING";
  return "UNKNOWN";
}

/* ---- W16 (option B) -- the binding-window fingerprint step ----------------------------------
 *
 * See ps4rf_kread.h for why this step exists. The five row indices come from the generated header
 * under neutral names, because the artefact gate reads THIS file for the subsystem names; the
 * selection itself lives in the registry (provenance = the revision candidate, STRICT identity), so
 * a table whose order ever changed cannot silently hand this step another window. The cursor is the
 * lifetime's own: a session re-arm never touches it, which is what makes "one window per lifetime"
 * structural instead of a convention.
 */
static uint32_t g_identity_cursor = 0u;

static const uint32_t g_identity_windows[PS4RF_KREAD_BINDING_WINDOW_COUNT] = {
  PS4RF_KREAD_BINDING_WINDOW_0, PS4RF_KREAD_BINDING_WINDOW_1, PS4RF_KREAD_BINDING_WINDOW_2,
  PS4RF_KREAD_BINDING_WINDOW_3, PS4RF_KREAD_BINDING_WINDOW_4,
};

uint32_t ps4rf_kread_identity_cursor(void) {
  return g_identity_cursor;
}

/* The row check, in the boot step's shape: the compiled row must be the window the generator
 * published under this slot -- exactly 16 bytes and a STRICT fingerprint identity. A row that
 * fails either check is refused before anything privileged happens and the step is not spent. */
static int kread_identity_row_ok(uint32_t slot, uint32_t *index_out) {
  const ps4rf_kread_region *row;
  uint32_t row_index;
  if (index_out == 0 || slot >= PS4RF_KREAD_BINDING_WINDOW_COUNT) return 0;
  row_index = g_identity_windows[slot];
  if (row_index >= PS4RF_KREAD_REGION_COUNT) return 0;
  row = &PS4RF_KREAD_REGIONS[row_index];
  if (row->length != PS4RF_KREAD_IDENTITY_LEN) return 0;
  if (row->identity_status != PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT) return 0;
  *index_out = row_index;
  return 1;
}

int ps4rf_kread_identity_next(ps4rf_kread_info *info, ps4rf_kread_identity_record *out) {
  uint32_t slot;
  uint32_t row_index = 0u;
  int run_status;

  if (info == 0 || out == 0) return PS4RF_KREAD_IDENTITY_INCOMPLETE;
  memset(out, 0, sizeof(*out));
  slot = g_identity_cursor;
  if (slot >= PS4RF_KREAD_BINDING_WINDOW_COUNT) {
    out->status = PS4RF_KREAD_IDENTITY_DONE;
    return PS4RF_KREAD_IDENTITY_DONE;
  }
  if (!kread_identity_row_ok(slot, &row_index)) {
    out->status = PS4RF_KREAD_IDENTITY_ROW;
    return PS4RF_KREAD_IDENTITY_ROW;   /* the cursor does not advance: nothing was attempted */
  }

  ps4rf_kread_session_begin(info);     /* this step's own one shot */
  run_status = ps4rf_kread_run(info, row_index, 0u, PS4RF_KREAD_IDENTITY_LEN);
  g_identity_cursor = slot + 1u;       /* spent, whatever the outcome: never retried */

  out->index = row_index;
  out->run_status = (int32_t)run_status;
  out->cb_status = info->cb_status;
  out->copied_len = info->copied_len;
  out->sha256_status = (uint32_t)info->sha256_status;
  out->resolved_rva = info->region_rva;
  if (run_status != PS4RF_KREAD_RUN_OK) {
    out->status = PS4RF_KREAD_IDENTITY_RUN_FAILED;
    return PS4RF_KREAD_IDENTITY_RUN_FAILED;
  }
  if (info->copied_len != PS4RF_KREAD_IDENTITY_LEN) {
    out->status = PS4RF_KREAD_IDENTITY_INCOMPLETE;
    return PS4RF_KREAD_IDENTITY_INCOMPLETE;
  }
  for (uint32_t i = 0u; i < PS4RF_KREAD_IDENTITY_LEN; i++) out->bytes[i] = info->bytes[i];
  for (uint32_t i = 0u; i < (uint32_t)sizeof(out->sha256); i++) out->sha256[i] = info->sha256[i];
  out->status = PS4RF_KREAD_IDENTITY_OK;
  return PS4RF_KREAD_IDENTITY_OK;
}

const char *ps4rf_kread_identity_status_name(int status) {
  if (status == PS4RF_KREAD_IDENTITY_OK) return "OK";
  if (status == PS4RF_KREAD_IDENTITY_DONE) return "SET_COMPLETE";
  if (status == PS4RF_KREAD_IDENTITY_ROW) return "BINDING_ROW_MISSING";
  if (status == PS4RF_KREAD_IDENTITY_RUN_FAILED) return "BINDING_READ_FAILED";
  if (status == PS4RF_KREAD_IDENTITY_INCOMPLETE) return "BINDING_INCOMPLETE";
  return "UNKNOWN";
}

/* ---- Track A -- the observation-window step --------------------------------------------------
 *
 * The twin of the binding-window step for the observation set (docs/P4-A-OBSERVATION-WINDOWS.md):
 * the keymgr slot pool and the five CCP/KeyMgr runtime windows. Same rules as the binding step --
 * a fixed step, one window per call, re-arming and spending the one shot itself, a lifetime cursor
 * a session re-arm never touches -- with the two differences the windows themselves dictate: the
 * read uses the ROW'S OWN length (8..2048 bytes of runtime state, never the fixed 16 of a
 * fingerprint), and a row that is not a STRUCTURAL_ONLY observation is refused before anything
 * privileged happens (and the cursor does not advance: nothing was attempted). The host records
 * these bytes as an observation; it never matches them as an identity.
 */
static uint32_t g_obs_cursor = 0u;

static const uint32_t g_obs_windows[PS4RF_KREAD_OBS_WINDOW_COUNT] = {
  PS4RF_KREAD_OBS_WINDOW_0, PS4RF_KREAD_OBS_WINDOW_1, PS4RF_KREAD_OBS_WINDOW_2,
  PS4RF_KREAD_OBS_WINDOW_3, PS4RF_KREAD_OBS_WINDOW_4, PS4RF_KREAD_OBS_WINDOW_5,
};

uint32_t ps4rf_kread_obs_cursor(void) {
  return g_obs_cursor;
}

/* The row check, in the binding step's shape: the compiled row must be the observation window the
 * generator published under this slot -- STRUCTURAL_ONLY, with a length the table itself fixes. */
static int kread_obs_row_ok(uint32_t slot, uint32_t *index_out, uint32_t *length_out) {
  const ps4rf_kread_region *row;
  uint32_t row_index;
  if (index_out == 0 || length_out == 0 || slot >= PS4RF_KREAD_OBS_WINDOW_COUNT) return 0;
  row_index = g_obs_windows[slot];
  if (row_index >= PS4RF_KREAD_REGION_COUNT) return 0;
  row = &PS4RF_KREAD_REGIONS[row_index];
  if (row->identity_status != PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY) return 0;
  if (row->length < 1u || row->length > PS4RF_KREAD_OBS_MAX_LEN) return 0;
  if (row->length > PS4RF_KREAD_MAX_LEN) return 0;
  *index_out = row_index;
  *length_out = row->length;
  return 1;
}

int ps4rf_kread_obs_next(ps4rf_kread_info *info, ps4rf_kread_observation_record *out) {
  uint32_t slot;
  uint32_t row_index = 0u;
  uint32_t length = 0u;
  int run_status;

  if (info == 0 || out == 0) return PS4RF_KREAD_OBS_INCOMPLETE;
  memset(out, 0, sizeof(*out));
  slot = g_obs_cursor;
  if (slot >= PS4RF_KREAD_OBS_WINDOW_COUNT) {
    out->status = PS4RF_KREAD_OBS_DONE;
    return PS4RF_KREAD_OBS_DONE;
  }
  if (!kread_obs_row_ok(slot, &row_index, &length)) {
    out->status = PS4RF_KREAD_OBS_ROW;
    return PS4RF_KREAD_OBS_ROW;        /* the cursor does not advance: nothing was attempted */
  }

  ps4rf_kread_session_begin(info);     /* this step's own one shot */
  run_status = ps4rf_kread_run(info, row_index, 0u, length);
  g_obs_cursor = slot + 1u;            /* spent, whatever the outcome: never retried */

  out->index = row_index;
  out->length = length;
  out->run_status = (int32_t)run_status;
  out->cb_status = info->cb_status;
  out->copied_len = info->copied_len;
  out->sha256_status = (uint32_t)info->sha256_status;
  out->resolved_rva = info->region_rva;
  if (run_status != PS4RF_KREAD_RUN_OK) {
    out->status = PS4RF_KREAD_OBS_RUN_FAILED;
    return PS4RF_KREAD_OBS_RUN_FAILED;
  }
  if (info->copied_len != length) {
    out->status = PS4RF_KREAD_OBS_INCOMPLETE;
    return PS4RF_KREAD_OBS_INCOMPLETE;
  }
  for (uint32_t i = 0u; i < length; i++) out->bytes[i] = info->bytes[i];
  for (uint32_t i = 0u; i < (uint32_t)sizeof(out->sha256); i++) out->sha256[i] = info->sha256[i];
  out->status = PS4RF_KREAD_OBS_OK;
  return PS4RF_KREAD_OBS_OK;
}

const char *ps4rf_kread_obs_status_name(int status) {
  if (status == PS4RF_KREAD_OBS_OK) return "OK";
  if (status == PS4RF_KREAD_OBS_DONE) return "SET_COMPLETE";
  if (status == PS4RF_KREAD_OBS_ROW) return "OBSERVATION_ROW_MISSING";
  if (status == PS4RF_KREAD_OBS_RUN_FAILED) return "OBSERVATION_READ_FAILED";
  if (status == PS4RF_KREAD_OBS_INCOMPLETE) return "OBSERVATION_INCOMPLETE";
  return "UNKNOWN";
}

const char *ps4rf_kread_cb_status_name(uint32_t status) {
  if (status == PS4RF_KREAD_CB_OK) return "OK";
  if (status == PS4RF_KREAD_CB_ARGS) return "ARGS_MISSING";
  if (status == PS4RF_KREAD_CB_MAGIC) return "CALLER_MARKER_MISSING";
  if (status == PS4RF_KREAD_CB_REGION) return "REGION_INDEX_INVALID";
  if (status == PS4RF_KREAD_CB_LENGTH) return "LENGTH_INVALID";
  if (status == PS4RF_KREAD_CB_OVERFLOW) return "OFFSET_OVERFLOW";
  if (status == PS4RF_KREAD_CB_CONTAINMENT) return "CROSS_REGION_REFUSED";
  if (status == PS4RF_KREAD_CB_LSTAR_SHAPE) return "LSTAR_SHAPE_INVALID";
  if (status == PS4RF_KREAD_CB_KBASE_MISMATCH) return "KBASE_CROSS_CHECK_MISMATCH";
  if (status == PS4RF_KREAD_CB_ADDRESS) return "RESOLVED_ADDRESS_INVALID";
  if (status == PS4RF_KREAD_CB_NOT_RUN) return "NOT_RUN";
  return "UNKNOWN";
}

const char *ps4rf_kread_run_status_name(int run_result) {
  if (run_result == PS4RF_KREAD_RUN_OK) return "OK";
  if (run_result == PS4RF_KREAD_RUN_ALREADY) return "SECOND_CALL_REFUSED";
  if (run_result == PS4RF_KREAD_RUN_KEXEC_FAILED) return "KEXEC_FAILED";
  if (run_result == PS4RF_KREAD_RUN_CALLBACK) return "CALLBACK_STOPPED";
  if (run_result == PS4RF_KREAD_RUN_RESULT_INVALID) return "RESULT_INVALID";
  if (run_result == PS4RF_KREAD_RUN_REQUEST_INVALID) return "REQUEST_REFUSED";
  if (run_result == PS4RF_KREAD_RUN_REGION_INDEX_INVALID) return "KREAD_REGION_INDEX_INVALID";
  if (run_result == PS4RF_KREAD_RUN_ARGUMENTS_INVALID) return "ARGUMENT_INVALID";
  return "UNKNOWN";
}

const char *ps4rf_kread_bye_reason(int run_result) {
  if (run_result == PS4RF_KREAD_RUN_REQUEST_INVALID) return "KREAD_REQUEST_REFUSED";
  if (run_result == PS4RF_KREAD_RUN_REGION_INDEX_INVALID) return "KREAD_REGION_INDEX_INVALID";
  if (run_result == PS4RF_KREAD_RUN_ARGUMENTS_INVALID) return "ARGUMENT_INVALID";
  return "KERNEL_READ_FAILED";
}

int ps4rf_kread_event_status(int run_result) {
  if (run_result == PS4RF_KREAD_RUN_OK) return PS4RF_KREAD_STATUS_OK;
  return PS4RF_KREAD_STATUS_READ_FAILED;
}

/* ------------------------------------------------------------------------ report */

static void hex_bytes(char *out, size_t cap, const uint8_t *data, uint32_t len) {
  static const char digits[] = "0123456789abcdef";
  size_t o = 0u;
  /* the bound must leave room for the two digits *and* the terminator of the final byte */
  for (uint32_t i = 0u; i < len && o + 2u < cap; i++) {
    out[o++] = digits[(data[i] >> 4) & 0xfu];
    out[o++] = digits[data[i] & 0xfu];
  }
  out[o] = '\0';
}

void ps4rf_kread_hex(char *out, size_t cap, const uint8_t *data, uint32_t len) {
  hex_bytes(out, cap, data, len);
}

static void u64_hex(char *out, uint64_t v) {
  static const char digits[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  out[0] = '0';
  out[1] = 'x';
  for (uint32_t i = 0u; i < 16u; i++) out[2u + i] = digits[(v >> (4u * (15u - i))) & 0xfull];
  out[18] = '\0';
}

/* Single-threaded session loop scratch for one hex-encoded read (no state is kept across
 * events; the buffer only exists because the maximum read hex-encodes to twice its
 * length). */
static char g_ps4rf_kread_hex[2u * PS4RF_KREAD_MAX_LEN + 1u];

static const char *identity_name(uint32_t status) {
  if (status == PS4RF_KREAD_IDENTITY_STRICT_FINGERPRINT) return "STRICT_FINGERPRINT";
  if (status == PS4RF_KREAD_IDENTITY_STRUCTURAL_ONLY) return "STRUCTURAL_ONLY";
  return "UNMEASURED";
}

jval *ps4rf_kread_event(const ps4rf_kread_info *info, int run_result,
                        const char *build_id, const char *label) {
  if (info == NULL) return NULL;
  jval *event = jval_new_object();
  if (event == NULL) return NULL;
  char buf[128];
  char off[24];
  char len_s[24];
  char sum_s[24];
  char rva_s[24];

  int executed = info->magic_out == PS4RF_KREAD_MAGIC_OUT;
  int measured = executed && info->cb_status == PS4RF_KREAD_CB_OK &&
                 info->copied_len >= 1u && info->copied_len <= PS4RF_KREAD_MAX_LEN &&
                 info->sha256_status == PS4RF_KREAD_SHA_MEASURED;
  uint32_t copied = measured ? info->copied_len : 0u;
  hex_bytes(g_ps4rf_kread_hex, sizeof(g_ps4rf_kread_hex), info->bytes, copied);
  char sha_hex[65];
  if (measured) {
    hex_bytes(sha_hex, sizeof(sha_hex), info->sha256, 32u);
  } else {
    sha_hex[0] = '\0';
  }
  u64_hex(buf, info->lstar);
  jval *j_lstar = jval_new_string(buf);
  u64_hex(buf, info->kbase_candidate);
  jval *j_kbase = jval_new_string(buf);
  u64_hex(buf, info->kbase_sdk);
  jval *j_kbase_sdk = jval_new_string(buf);
  /* nothing about the source or the request may look measured when the callback never ran */
  if (executed) {
    u64_hex(rva_s, info->region_rva);
  } else {
    rva_s[0] = 'U'; rva_s[1] = 'N'; rva_s[2] = 'M'; rva_s[3] = 'E'; rva_s[4] = 'A';
    rva_s[5] = 'S'; rva_s[6] = 'U'; rva_s[7] = 'R'; rva_s[8] = 'E'; rva_s[9] = 'D';
    rva_s[10] = '\0';
  }
  snprintf(off, sizeof(off), "%u", (unsigned)info->offset);
  snprintf(len_s, sizeof(len_s), "%u", (unsigned)info->length);
  if (executed) {
    u64_hex(sum_s, info->offset_length_sum);
  } else {
    sum_s[0] = 'U'; sum_s[1] = 'N'; sum_s[2] = 'M'; sum_s[3] = 'E'; sum_s[4] = 'A';
    sum_s[5] = 'S'; sum_s[6] = 'U'; sum_s[7] = 'R'; sum_s[8] = 'E'; sum_s[9] = 'D';
    sum_s[10] = '\0';
  }
  char rres_s[24];
  char addr_s[24];
  if (executed && info->resolved_rva != 0ull) {
    u64_hex(rres_s, info->resolved_rva);
  } else {
    rres_s[0] = 'U'; rres_s[1] = 'N'; rres_s[2] = 'M'; rres_s[3] = 'E'; rres_s[4] = 'A';
    rres_s[5] = 'S'; rres_s[6] = 'U'; rres_s[7] = 'R'; rres_s[8] = 'E'; rres_s[9] = 'D';
    rres_s[10] = '\0';
  }
  /* the scope line carries the bound the module actually compiled: it is the generated header's
   * value, which is the registry's value (no second definition lives in this file) */
  char scope_s[192];
  snprintf(scope_s, sizeof(scope_s),
           "read-only; one bounded privileged callback per session; region table compile-time; "
           "max %u; no kernel write; no generic primitive", (unsigned)PS4RF_KREAD_MAX_LEN);
  if (executed && info->resolved_runtime_va != 0ull) {
    u64_hex(addr_s, info->resolved_runtime_va);
  } else {
    addr_s[0] = 'U'; addr_s[1] = 'N'; addr_s[2] = 'M'; addr_s[3] = 'E'; addr_s[4] = 'A';
    addr_s[5] = 'S'; addr_s[6] = 'U'; addr_s[7] = 'R'; addr_s[8] = 'E'; addr_s[9] = 'D';
    addr_s[10] = '\0';
  }
  const char *region_name = executed && info->region_index < PS4RF_KREAD_REGION_COUNT
                                ? PS4RF_KREAD_REGIONS[info->region_index].name
                                : "UNKNOWN";
  const char *region_identity = executed && info->region_index < PS4RF_KREAD_REGION_COUNT
                                    ? identity_name(
                                          PS4RF_KREAD_REGIONS[info->region_index].identity_status)
                                    : "UNMEASURED";
  const char *cross_str = !executed ? "UNMEASURED"
                           : (info->cross_check == 1ull
                                  ? "MATCH"
                                  : (info->kbase_candidate != 0ull ? "MISMATCH" : "UNMEASURED"));
  const char *cb_name = executed ? ps4rf_kread_cb_status_name(info->cb_status)
                                 : "NOT_EXECUTED";

  if (jval_obj_set(event, "msg", jval_new_string("EVENT")) != 0 ||
      jval_obj_set(event, "event", jval_new_string("kernel.read.bounded")) != 0 ||
      jval_obj_set(event, "schema", jval_new_string("ps4rf.kernel.read.bounded.v1")) != 0 ||
      jval_obj_set(event, "status", jval_new_string(run_result == PS4RF_KREAD_RUN_OK
                                                         ? "OK" : "FAILED")) != 0 ||
      jval_obj_set(event, "run_status",
                   jval_new_int((int64_t)ps4rf_kread_event_status(run_result))) != 0 ||
      jval_obj_set(event, "run_status_name",
                   jval_new_string(ps4rf_kread_run_status_name(run_result))) != 0 ||
      jval_obj_set(event, "callback_executed", jval_new_bool(executed)) != 0 ||
      jval_obj_set(event, "cb_status", jval_new_int((int64_t)info->cb_status)) != 0 ||
      jval_obj_set(event, "cb_status_name", jval_new_string(cb_name)) != 0 ||
      jval_obj_set(event, "kexec_rc", jval_new_int((int64_t)info->kexec_rc)) != 0 ||
      jval_obj_set(event, "requested_region", jval_new_string(region_name)) != 0 ||
      jval_obj_set(event, "requested_region_index", jval_new_int((int64_t)info->region_index)) != 0 ||
      jval_obj_set(event, "region_identity", jval_new_string(region_identity)) != 0 ||
      jval_obj_set(event, "region_rva", jval_new_string(rva_s)) != 0 ||
      jval_obj_set(event, "requested_offset", jval_new_string(off)) != 0 ||
      jval_obj_set(event, "requested_length", jval_new_string(len_s)) != 0 ||
      jval_obj_set(event, "copied_len", jval_new_int((int64_t)info->copied_len)) != 0 ||
      jval_obj_set(event, "offset_length_sum", jval_new_string(sum_s)) != 0 ||
      jval_obj_set(event, "lstar", j_lstar) != 0 ||
      jval_obj_set(event, "kbase_candidate", j_kbase) != 0 ||
      jval_obj_set(event, "kbase_sdk", j_kbase_sdk) != 0 ||
      jval_obj_set(event, "cross_check", jval_new_string(cross_str)) != 0 ||
      jval_obj_set(event, "resolved_rva", jval_new_string(rres_s)) != 0 ||
      jval_obj_set(event, "resolved_runtime_va", jval_new_string(addr_s)) != 0 ||
      jval_obj_set(event, "bytes_hex", jval_new_string(g_ps4rf_kread_hex)) != 0 ||
      jval_obj_set(event, "sha256", jval_new_string(sha_hex)) != 0 ||
      jval_obj_set(event, "sha256_status", jval_new_string(
                     info->sha256_status == PS4RF_KREAD_SHA_MEASURED ? "MEASURED"
                                                                     : "NOT_MEASURED")) != 0 ||
      jval_obj_set(event, "max_read_len", jval_new_int((int64_t)PS4RF_KREAD_MAX_LEN)) != 0 ||
      jval_obj_set(event, "region_count", jval_new_int((int64_t)PS4RF_KREAD_REGION_COUNT)) != 0 ||
      jval_obj_set(event, "single_callback", jval_new_bool(1)) != 0 ||
      jval_obj_set(event, "retry", jval_new_bool(0)) != 0 ||
      jval_obj_set(event, "writes_to_kernel", jval_new_bool(0)) != 0 ||
      jval_obj_set(event, "host_supplied_address", jval_new_bool(0)) != 0 ||
      jval_obj_set(event, "generic_read_primitive",
                   jval_new_string("NONE: one bounded region read per session; the host picks "
                                   "region index, offset and length, never an address")) != 0 ||
      jval_obj_set(event, "resolved_runtime_va_note",
                   jval_new_string("the resolved address lives in this evidence only; the "
                                   "request carries no address and cannot contain one")) != 0 ||
      jval_obj_set(event, "build_id", jval_new_string(build_id != NULL ? build_id : "")) != 0 ||
      jval_obj_set(event, "label", jval_new_string(label != NULL ? label : "")) != 0 ||
      jval_obj_set(event, "provider", jval_new_string("ps4rfd-kread-privileged")) != 0 ||
      jval_obj_set(event, "scope", jval_new_string(scope_s)) != 0 ||
      jval_obj_set(event, "profile_decision", jval_new_string("PROFILE_UNBOUND")) != 0) {
    jval_free(event);
    return NULL;
  }
  return event;
}
