/* PS4RF W9 - read-only kernel attestation (the only privileged path in W9).
 *
 * Design rules that the code must keep (owner W9 brief):
 *   - fixed, compile-time measurement set only (ps4rf_attest_data.h, generated from pinned
 *     FW13.52 evidence); the host supplies no address, only a magic word and a buffer.
 *   - exactly ONE privileged entry point: ps4rf_attest_kpayload, called through the SDK's
 *     kexec() exactly once per session (one-shot guard, no retry loop).
 *   - read-only: rdmsr(LSTAR) + bounded reads of the table RVAs + writes into the caller's
 *     own info block. No kernel writes, no allocation, no callbacks, no indirect calls.
 *   - fail closed: a bad LSTAR shape, a non-canonical base or a failed image identity stops
 *     the callback before any further read.
 *
 * The section split is a build gate: everything named ps4rf_attest_k* / ps4rf_attest_kpayload
 * is the kernel section (privileged instructions allowed there only), everything else is the
 * user section (no kernel RVA constants, no absolute kernel pointers).
 */

#ifndef PS4RF_ATTEST_H
#define PS4RF_ATTEST_H

#include <stdint.h>

#include "ps4rf_attest_data.h"
#include "ps4rf_protocol.h"   /* jval, for the event body */

#define PS4RF_ATTEST_MAGIC_IN 0x57524B41u    /* "AKRW" - caller marker, proves buffer access */
#define PS4RF_ATTEST_MAGIC_OUT 0x57524B42u   /* "BKWR" - written by the callback            */
#define PS4RF_ATTEST_GUARD 0x5053345246415439ull  /* "PS4RFAT9" - struct end canary         */

/* callback status */
#define PS4RF_ATTEST_CB_OK 0u
#define PS4RF_ATTEST_CB_ARGS 1u           /* args or info pointer missing                     */
#define PS4RF_ATTEST_CB_MAGIC 2u          /* caller marker missing: wrong buffer              */
#define PS4RF_ATTEST_CB_LSTAR_SHAPE 3u    /* LSTAR not canonical / page offset != 0x1C0        */
#define PS4RF_ATTEST_CB_IMAGE 4u          /* image identity (ELF header) mismatch             */

/* per-entry status */
#define PS4RF_ATTEST_ENTRY_MATCH 0u
#define PS4RF_ATTEST_ENTRY_MISMATCH 1u
#define PS4RF_ATTEST_ENTRY_STRUCT_OK 2u    /* STRUCTURAL_ONLY observation, in range */
#define PS4RF_ATTEST_ENTRY_STRUCT_BAD 3u   /* STRUCTURAL_ONLY observation, out of range:
                                            * recorded evidence, never a failure on its own */

/* userland driver result */
#define PS4RF_ATTEST_RUN_OK 0
#define PS4RF_ATTEST_RUN_ALREADY 1         /* one-shot: a second call is refused               */
#define PS4RF_ATTEST_RUN_KEXEC_FAILED 2
#define PS4RF_ATTEST_RUN_CALLBACK 3        /* callback reported a failure status               */
#define PS4RF_ATTEST_RUN_RESULT_INVALID 4  /* magic_out / guard / counters inconsistent        */

#define PS4RF_ATTEST_ENTRY_MAX PS4RF_ATTEST_ENTRY_COUNT

typedef struct {
  uint32_t status;
  uint32_t observed_len;
  uint8_t observed[PS4RF_ATTEST_MAX_LEN];
} ps4rf_attest_entry_result;

typedef struct {
  uint32_t magic_in;        /* +0x00 in : PS4RF_ATTEST_MAGIC_IN */
  uint32_t magic_out;       /* +0x04 out: PS4RF_ATTEST_MAGIC_OUT */
  uint32_t cb_status;       /* +0x08 out: callback status */
  uint32_t entry_count;     /* +0x0c out */
  uint64_t lstar;           /* +0x10 out: observed LSTAR */
  uint64_t kbase_lstar;     /* +0x18 out: LSTAR - PS4RF_XFAST_SYSCALL_RVA (candidate) */
  uint64_t kbase_sdk;       /* +0x20 in : get_kernel_base() measured in userland */
  uint64_t aperture;        /* +0x28 out: STRUCTURAL_ONLY observation value */
  uint64_t slide;           /* +0x30 out: kbase - static image base (KASLR slide) */
  /* Scoring is strict-only. STRUCTURAL_ONLY windows are counted as observations and can never
   * change the strict figures, the event status or the run status. */
  uint32_t strict_matches;          /* +0x38 out: STRICT_FINGERPRINT windows matching */
  uint32_t strict_mismatches;       /* +0x3c out: STRICT_FINGERPRINT windows not matching */
  uint32_t structural_observations; /* +0x40 out: STRUCTURAL_ONLY windows measured */
  uint32_t read_count;      /* +0x40 out: how many table reads were performed */
  int32_t kexec_rc;         /* +0x44 out: return value of the kexec() syscall */
  ps4rf_attest_entry_result entries[PS4RF_ATTEST_ENTRY_MAX];  /* +0x48 .. */
  uint64_t guard;           /* last field: PS4RF_ATTEST_GUARD proves the write covered it */
} ps4rf_attest_info;

/* kernel-side ABI: the kernel builds { void *syscall_handler; void *arg; } and puts our
 * pointer in the second field, exactly like the SDK's kpayload_dump path. */
struct ps4rf_attest_args {
  void *syscall_handler;
  ps4rf_attest_info *info;
};

/* ---- kernel section (privileged instructions only here) -------------------------------- */

int ps4rf_attest_kpayload(void *td, struct ps4rf_attest_args *args);

/* Leaf operations of the measurement (weak definitions in the implementation file; the
 * offline harness in tests/harness replaces them to exercise this exact code path). */
uint64_t ps4rf_attest_k_readmsr(uint32_t reg);
uint8_t ps4rf_attest_k_read8(uint64_t base, uint32_t rva);

/* pure helpers, shared by the callback and the host tests */
uint64_t ps4rf_attest_k_expected_u64(const uint8_t *expected, uint64_t slide, uint32_t kind);
int ps4rf_attest_k_lstar_ok(uint64_t lstar);
int ps4rf_attest_k_pointer_ok(uint64_t value);

/* ---- user section ---------------------------------------------------------------------- */

/* Runs the single privileged callback. Returns PS4RF_ATTEST_RUN_*; the second call in the
 * same session returns PS4RF_ATTEST_RUN_ALREADY and executes nothing. */
int ps4rf_attest_run(ps4rf_attest_info *info);
int ps4rf_attest_validate_result(const ps4rf_attest_info *info);

/* Names for the report (frozen strings, used by the payload event and the host report). */
const char *ps4rf_attest_cb_status_name(uint32_t status);
const char *ps4rf_attest_entry_status_name(uint32_t status);

/* Builds the attestation event body (canonical JSON, sent as one sealed EVENT frame).
 * Returns NULL on allocation failure. The caller owns the result. */
jval *ps4rf_attest_event(const ps4rf_attest_info *info, int run_status,
                         const char *build_id, const char *label);

#endif /* PS4RF_ATTEST_H */
