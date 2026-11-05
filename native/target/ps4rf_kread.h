/* PS4RF W12 -- one bounded `kernel.read` provider callback (the only privileged path in W12).
 *
 * Rules this file and its implementation keep (owner W12 brief, docs/P4-W12-KERNEL-READ-PROVIDER.md):
 *   - exactly ONE privileged entry point: ps4rf_kread_kpayload, reached through the SDK's
 *     kexec() exactly once per session (one-shot guard set BEFORE kexec, no retry, no loop)
 *   - the host supplies no address: the request is (region index, offset, length) only. The
 *     region's RVA comes from the generated compile-time table
 *     (native/target/ps4rf_kread_regions.h, produced by gen_kread_regions.py from the active
 *     region registry), the address is composed inside the callback as kbase + region_rva +
 *     offset. There is no `addr` field anywhere.
 *   - bounds: max single read PS4RF_KREAD_MAX_LEN (owned by the registry, carried into
 *     the generated header), zero length refused, 32 bit checked
 *     add (wraparound refused), region containment (offset + length <= region length; a
 *     cross-region read is refused), canonical resolved address, all before the first byte read.
 *   - kbase only by the proven W9/W11.2 relation: LSTAR -> shape gate -> LSTAR - 0x1C0,
 *     cross-checked *inside the callback* against the SDK's own kernel base before a single
 *     byte is read.
 *   - read-only: the callback writes only into the payload's own result block (never kernel
 *     memory, not even a status word: a block that does not carry the caller marker is left
 *     untouched and the callback returns). Failures are reported in that block.
 *   - no writes to the caller's block before the one-shot guard; no function pointer from the
 *     host; no arbitrary kernel call; no retry loop; no syscall table or persistent state
 *     change; no allocation; no locking; no GPUVM/KeyMgr/CCP/SAMU.
 *
 * Section split, enforced by the build gates: everything named ps4rf_kread_k* is the kernel
 * section (the privileged instruction and the bounded copy), everything else is the user
 * section (no kernel RVA constant baked in beyond the generated table, no absolute kernel
 * pointer).
 */

#ifndef PS4RF_KREAD_H
#define PS4RF_KREAD_H

#include <stdint.h>

/* size_t, for the report helpers' buffer bounds */
#include <stddef.h>

/* The bounded region table AND the one read bound both come from the generated header: the
 * single owner of the bound and of the region policy is the host registry, never this module. */
#include "ps4rf_kread_regions.h"

#include "ps4rf_protocol.h"   /* jval, for the sealed event body */

#define PS4RF_KREAD_MAGIC_IN 0x44524B43u             /* "CKRD" caller marker            */
#define PS4RF_KREAD_MAGIC_OUT 0x44524B44u            /* "DKRD" callback marker          */
#define PS4RF_KREAD_GUARD 0x50533452464B5231ull      /* "PS4RFKR1" struct end canary    */

/* callback status (kernel section) */
#define PS4RF_KREAD_CB_OK 0u
#define PS4RF_KREAD_CB_ARGS 1u            /* args or info pointer missing                        */
#define PS4RF_KREAD_CB_MAGIC 2u           /* caller marker missing: wrong buffer, nothing written */
#define PS4RF_KREAD_CB_REGION 3u          /* region index outside the generated table            */
#define PS4RF_KREAD_CB_LENGTH 4u          /* length 0 or above PS4RF_KREAD_MAX_LEN               */
#define PS4RF_KREAD_CB_OVERFLOW 5u        /* offset + length (or rva + offset) wraps             */
#define PS4RF_KREAD_CB_CONTAINMENT 6u     /* offset + length crosses the region end              */
#define PS4RF_KREAD_CB_LSTAR_SHAPE 7u     /* not canonical / page offset != 0x1C0                */
#define PS4RF_KREAD_CB_KBASE_MISMATCH 8u  /* LSTAR base != SDK base: read nothing                */
#define PS4RF_KREAD_CB_ADDRESS 9u         /* resolved address not canonical                      */
#define PS4RF_KREAD_CB_NOT_RUN 255u       /* refused in the user section before kexec            */

/* run result (user section) */
#define PS4RF_KREAD_RUN_OK 0
#define PS4RF_KREAD_RUN_ALREADY 1             /* one-shot: a second call is refused            */
#define PS4RF_KREAD_RUN_KEXEC_FAILED 2
#define PS4RF_KREAD_RUN_CALLBACK 3            /* callback reported a failure status            */
#define PS4RF_KREAD_RUN_RESULT_INVALID 4      /* magic_out / guard / counts inconsistent       */
#define PS4RF_KREAD_RUN_REQUEST_INVALID 5     /* refused before kexec: nothing was attempted   */
#define PS4RF_KREAD_RUN_REGION_INDEX_INVALID 6 /* refused before kexec: the request names no row
                                                * of the compile-time table (W13-C1)             */
#define PS4RF_KREAD_RUN_ARGUMENTS_INVALID 7    /* refused before every bound rule and before any
                                                * kexec: the request arguments are missing,
                                                * wrongly typed or out of range (W13-C2)         */

/* ---- W15R2: the lifetime boot binding (the FIXED step, not a request) -----------------------
 * The resident agent measures the boot instant exactly ONCE per agent lifetime through the same
 * single privileged callback the research read uses, over the compiled `boottime` row. The row
 * index is a compile-time constant of the generated table; nothing about this step comes from a
 * request, from the host or from a runtime address. The decoded timeval is cached in the agent's
 * lifetime state and announced by every session of that lifetime; deriving the canonical W11 boot
 * id from it stays a host-side act (tools/profiles/bootid.py). These codes are the payload's own
 * refusal vocabulary: the authoritative validation of the binding is the host's. */
#define PS4RF_KREAD_BOOT_OK 0
#define PS4RF_KREAD_BOOT_RUN_FAILED 1      /* the bounded read itself did not return OK       */
#define PS4RF_KREAD_BOOT_INCOMPLETE 2      /* short copy or an unfilled result block          */
#define PS4RF_KREAD_BOOT_SEC 3             /* tv_sec <= 0: uninitialised timeval              */
#define PS4RF_KREAD_BOOT_USEC 4            /* tv_usec outside 0..999999                       */
#define PS4RF_KREAD_BOOT_FLOOR 5           /* before the plausibility floor of the host rule  */
#define PS4RF_KREAD_BOOT_FUTURE 6          /* after the console's own wall clock              */
#define PS4RF_KREAD_BOOT_ROW 7             /* the generated table serves no boottime row      */

/* ---- W16 (option B): the binding-window fingerprint steps (FIXED steps, not requests) --------
 * The owner's decision of 2026-10-07: the five STRICT binding windows of the revision candidate
 * are fingerprints, not research data -- the W13 review keeps them IDENTITY_ONLY on purpose, so no
 * release may be minted for them and the request-driven read path must never serve them, while the
 * promotion of that candidate needs exactly one live byte match per window. The payload therefore
 * reads them itself, one window per session, after the lifetime's boot binding was measured in an
 * earlier session. Every rule of the boot step applies unchanged: a compile-time row index of the
 * generated table (neutral names), offset 0, 16 bytes, the step re-arms the one shot itself and
 * spends it in exactly one read, and the outcome is reported, never retried and never guessed. The
 * host is the judge: it compares the reported bytes against the pinned image. */
#define PS4RF_KREAD_IDENTITY_LEN 16u
#define PS4RF_KREAD_IDENTITY_OK 0          /* the window was read; bytes + sha256 are valid    */
#define PS4RF_KREAD_IDENTITY_DONE 1        /* every window of the set was read in this lifetime */
#define PS4RF_KREAD_IDENTITY_ROW 2         /* the table serves no such window (row check failed) */
#define PS4RF_KREAD_IDENTITY_RUN_FAILED 3  /* the bounded read itself did not return OK        */
#define PS4RF_KREAD_IDENTITY_INCOMPLETE 4  /* short copy or an unfilled result block           */

/* ---- Track A: the observation-window step (FIXED step, not a request) -----------------------
 * The same owner decision covers the read-only *observations* of the Track A campaign
 * (docs/P4-A-OBSERVATION-WINDOWS.md): the keymgr slot pool and five CCP/KeyMgr runtime windows
 * (K-L1 / CCP-L1). They are STRUCTURAL_ONLY by rule -- bytes that change within a boot, so a
 * fingerprint of them would fail a healthy console -- and they are read the same way the binding
 * windows are: by the payload itself, ONE window per session, on a cursor of this lifetime, after
 * the binding set is exhausted. Session 1 spends its single privileged transition on the boot
 * binding, sessions 2..6 read the five binding windows, sessions 7..12 read these six observation
 * windows; the "one privileged transition per session" invariant stays literal. The row index is a
 * compile-time constant of the generated table, the offset is 0, the length is the row's own, and
 * no host value reaches this step. The host records the bytes as an observation -- it never
 * matches them as an identity. */
#define PS4RF_KREAD_OBS_OK 0               /* the window was read; bytes + sha256 are valid    */
#define PS4RF_KREAD_OBS_DONE 1             /* every window of the set was read in this lifetime */
#define PS4RF_KREAD_OBS_ROW 2              /* the table serves no such window (row check failed) */
#define PS4RF_KREAD_OBS_RUN_FAILED 3       /* the bounded read itself did not return OK        */
#define PS4RF_KREAD_OBS_INCOMPLETE 4       /* short copy or an unfilled result block           */

/* sha256_status */
#define PS4RF_KREAD_SHA_NOT_MEASURED 0u       /* no complete copy: the explicit not-measured marker */
#define PS4RF_KREAD_SHA_MEASURED 1u

/* flags: the callback's contract, proven by the manifest gate and by the offline harness */
#define PS4RF_KREAD_FLAG_SINGLE_CALLBACK 0x1u
#define PS4RF_KREAD_FLAG_NO_RETRY 0x2u
#define PS4RF_KREAD_FLAG_NO_KERNEL_WRITE 0x4u
#define PS4RF_KREAD_FLAG_NO_HOST_ADDRESS 0x8u

/* event run_status ids (the same vocabulary the host re-derives) */
#define PS4RF_KREAD_STATUS_OK 0
#define PS4RF_KREAD_STATUS_READ_FAILED 1

/* validation status strings */
#define PS4RF_KREAD_VAL_OK "OK"
#define PS4RF_KREAD_VAL_NOT_READ "NOT_READ"

typedef struct {
  uint32_t magic_in;          /* in  : PS4RF_KREAD_MAGIC_IN                                */
  uint32_t cb_status;         /* out : callback status                                     */
  uint32_t run_status;        /* out : user-section verdict                                */
  uint32_t region_index;      /* in  : index into the generated compile-time region table  */
  uint32_t offset;            /* in  : byte offset inside that region                      */
  uint32_t length;            /* in  : requested length, 1..PS4RF_KREAD_MAX_LEN            */
  uint32_t copied_len;        /* out : bytes copied by the callback (0 on any refusal)     */
  uint32_t sha256_status;     /* out : PS4RF_KREAD_SHA_NOT_MEASURED / _MEASURED            */
  uint32_t flags;             /* out : PS4RF_KREAD_FLAG_*                                   */
  int32_t kexec_rc;           /* out : kexec() return code                                 */
  uint32_t reserved0;         /* must stay 0; never host controlled                        */
  uint32_t reserved1;         /* must stay 0; never host controlled                        */
  uint64_t lstar;             /* out : observed LSTAR                                      */
  uint64_t kbase_candidate;   /* out : lstar - 0x1C0                                       */
  uint64_t kbase_sdk;         /* in  : the SDK's own kernel base (set before kexec)        */
  uint64_t region_rva;        /* out : echo of the region's compile-time RVA               */
  uint64_t resolved_rva;      /* out : region_rva + offset (checked)                       */
  uint64_t resolved_runtime_va; /* out : kbase + resolved_rva (canonical, checked). This is
                                *       payload-side EVIDENCE only: it is written by the
                                *       callback and read by validate()/the event, and it is
                                *       never an input, never read back into an address.    */
  uint64_t offset_length_sum; /* out : the checked offset + length sum                     */
  uint64_t cross_check;       /* out : 1 = candidate == SDK base                           */
  uint8_t bytes[PS4RF_KREAD_MAX_LEN];  /* out : the exactly requested bytes, nothing else   */
  uint8_t sha256[32];         /* out : SHA-256 of bytes[0..copied_len) when measured       */
  uint64_t magic_out;         /* out : PS4RF_KREAD_MAGIC_OUT                               */
  uint64_t guard;             /* out : PS4RF_KREAD_GUARD                                   */
} ps4rf_kread_info;

/* The console's single privileged transition does not hand the payload its block directly: the
 * kernel builds a wrapper around the syscall-11 argument and passes a pointer to it, so the
 * caller's block sits in the *second* field (the W9 live run proved the shape; W11.2 carries
 * the same first field). Without it the callback would read the kernel's syscall handler as its
 * result block and any failure report would write into kernel memory -- a forbidden write. */
struct ps4rf_kread_args {
  void *syscall_handler;      /* first field of the kernel's syscall-11 wrapper: never touched */
  ps4rf_kread_info *info;     /* the payload's own result block; no address, no length */
};
typedef struct ps4rf_kread_args ps4rf_kread_args;

/* W16 (option B): one binding window's outcome, copied out of the scratch block before the next
 * step clears it. The bytes are reported raw: the payload makes no match claim and no hash claim
 * beyond its own measurement (the host re-derives both). `index` is the compiled table row, never a
 * host value. Declared after the info block on purpose -- the W12 gate parses the info layout from
 * the first `typedef struct {` in this header, so a struct must not be inserted before it. */
typedef struct {
  uint32_t index;             /* the compiled table row this record describes              */
  int      status;            /* PS4RF_KREAD_IDENTITY_*                                    */
  int32_t  run_status;        /* the module's own verdict for the read                     */
  uint32_t cb_status;         /* the callback's status                                     */
  uint32_t copied_len;        /* bytes the callback copied (0 on any refusal)              */
  uint32_t sha256_status;     /* PS4RF_KREAD_SHA_NOT_MEASURED / _MEASURED                  */
  uint64_t resolved_rva;      /* echo of the row's compile-time RVA (offset 0)             */
  uint8_t  bytes[PS4RF_KREAD_IDENTITY_LEN];   /* out: exactly the window, when OK             */
  uint8_t  sha256[32];        /* out: SHA-256 of bytes[0..copied_len), when measured        */
} ps4rf_kread_identity_record;

/* Track A: one observation window's outcome. Same shape as the identity record, but the window is
 * runtime state (STRUCTURAL_ONLY) and its length is the row's own, up to PS4RF_KREAD_OBS_MAX_LEN.
 * The bytes are reported raw: the payload claims nothing about them beyond its own measurement,
 * and the host records them as an observation. Declared after the info block for the same reason
 * as the identity record (the W12 gate parses the info layout from the first `typedef struct {`
 * in this header, so a struct must not be inserted before it). */
typedef struct {
  uint32_t index;             /* the compiled table row this record describes              */
  int      status;            /* PS4RF_KREAD_OBS_*                                         */
  int32_t  run_status;        /* the module's own verdict for the read                     */
  uint32_t cb_status;         /* the callback's status                                     */
  uint32_t copied_len;        /* bytes the callback copied (0 on any refusal)              */
  uint32_t length;            /* the row's own length: what the step asked for              */
  uint32_t sha256_status;     /* PS4RF_KREAD_SHA_NOT_MEASURED / _MEASURED                  */
  uint64_t resolved_rva;      /* echo of the row's compile-time RVA (offset 0)             */
  uint8_t  bytes[PS4RF_KREAD_OBS_MAX_LEN];  /* out: exactly the window, when OK            */
  uint8_t  sha256[32];        /* out: SHA-256 of bytes[0..copied_len), when measured        */
} ps4rf_kread_observation_record;

/* kernel section */
int ps4rf_kread_kpayload(void *td, struct ps4rf_kread_args *args);
int ps4rf_kread_k_lstar_ok(uint64_t lstar);

/* user section */
int ps4rf_kread_run(ps4rf_kread_info *info, uint32_t region_index, uint32_t offset,
                    uint32_t length);
int ps4rf_kread_validate(const ps4rf_kread_info *info);
/* W13-C2 request contract (wire catalog revision R2: kernel.read bounded-region args). The
 * request carries exactly three integers under body.arguments -- region_index, offset, length --
 * and never an address, an rva, a pointer or a size of any address space. The parse is total and
 * strict: a field that is missing, not an integer, negative or outside its 32 bit range makes the
 * whole request invalid, and an invalid request is refused explicitly (ARGUMENTS_INVALID, before
 * every bound rule and before any kexec) instead of being replaced by a sentinel that a later rule
 * could read as a value. There is no default region, no probe and no second read path.
 *
 * The parse itself lives outside this module: the generated argument catalog (which the router
 * applies before any provider entry) fixes the three required integer fields, and the wired
 * bounded provider (native/target/ps4rf_stub.c) reads them from the *validated* argument object
 * and passes plain integers here. This module never sees host input -- no jval, no key name, no
 * bytes of the request reach it, which the build gate asserts.
 * What the module owns is the refusal of a request the trigger could not parse. */
int ps4rf_kread_refuse_arguments(ps4rf_kread_info *info);
/* W14 (resident ps4rfd): re-arm the one shot. Called exactly once at the start of a session --
 * never from a request, never from a handler. The resident agent serves many authenticated
 * sessions per boot and the authorization is not persistent (one release record per read), so the
 * structural guard is per session: at most one privileged transition per session, and each of
 * them needs its own release on the host side. */
void ps4rf_kread_session_begin(ps4rf_kread_info *info);
/* W15R2: the lifetime boot binding. One fixed step per agent lifetime, called by the resident
 * bootstrap only -- never from a handler, never from a request. It re-arms and spends the one
 * shot itself (a session re-arms afterwards, so the session's own read is unaffected), reads
 * exactly the compiled `boottime` row through the one kexec call site and decodes the two little
 * endian int64 fields of the struct timeval. Returns a PS4RF_KREAD_BOOT_* code; on anything but
 * OK the caller must keep its lifetime UNRESOLVED (no guessed instant, no fallback value). */
int ps4rf_kread_boot_binding(ps4rf_kread_info *info, long long *sec, long long *usec);
/* W15R3: the lifetime's boot-binding verdict for the privileged gates. True only after the one
 * fixed measurement returned OK; a lifetime the measurement could not resolve returns false, and
 * the privileged provider then refuses the request before it enters anything. Set by the
 * measurement itself, never by a request, never by the read path. */
int ps4rf_kread_boot_established(void);
/* W15R3: the daemon accepts a lifetime binding that the platform route measured (the W11 sysctl
 * route: on a build where that hook answers, it is the same fact, measured elsewhere). The module
 * records it so the privileged gate sees ONE binding state per lifetime, whatever measured it --
 * the console build never takes this path (its hook is dead), the rehearsal does. A later failed
 * measurement clears the state again (ps4rf_kread_boot_binding starts fail-closed). */
void ps4rf_kread_boot_record_platform(void);
const char *ps4rf_kread_boot_status_name(int status);
/* W16 (option B): the lifetime's binding-window step. Called by the agent's fixed step -- never
 * from a handler, never from a request -- once per session, after the lifetime's boot binding was
 * measured in an EARLIER session (session 1 spends its one shot on the binding, so the windows
 * start in session 2 and the "one privileged transition per session" invariant stays literal).
 * Each call re-arms the one shot, reads exactly ONE window (compile-time row, offset 0, 16 bytes)
 * and copies the outcome into `out`; the monotonic lifetime cursor advances whether the read
 * succeeded or not, so a window is never read twice and a failed one is never retried. Returns a
 * PS4RF_KREAD_IDENTITY_* code; PS4RF_KREAD_IDENTITY_DONE means the set is exhausted. */
int ps4rf_kread_identity_next(ps4rf_kread_info *info, ps4rf_kread_identity_record *out);
/* evidence only: how many steps of this lifetime were spent (0..count) */
uint32_t ps4rf_kread_identity_cursor(void);
const char *ps4rf_kread_identity_status_name(int status);
/* Track A: the lifetime's observation-window step. Same contract as the identity step, with two
 * differences that follow from what these windows are: (1) it runs only after the binding set is
 * exhausted (the daemon asks for it only then), so the sessions read binding first and observation
 * second, and (2) the window is a STRUCTURAL_ONLY runtime-state row, read at offset 0 with the
 * ROW'S OWN length (1..PS4RF_KREAD_OBS_MAX_LEN) -- the step refuses a row that is not such a
 * window before anything privileged happens and does not spend its shot on it. The cursor is the
 * lifetime's own: one window per call, never a second attempt at the same row. Returns a
 * PS4RF_KREAD_OBS_* code; PS4RF_KREAD_OBS_DONE means the set is exhausted. */
int ps4rf_kread_obs_next(ps4rf_kread_info *info, ps4rf_kread_observation_record *out);
/* evidence only: how many observation steps of this lifetime were spent (0..count) */
uint32_t ps4rf_kread_obs_cursor(void);
const char *ps4rf_kread_obs_status_name(int status);
/* The fixed steps' report helper: lowercase hex of `len` bytes into `out`, always NUL terminated
 * and bounded by `cap` (a value that does not fit is truncated, never overrun). Exported so the
 * daemon hex-encodes a window exactly once, in one place. */
void ps4rf_kread_hex(char *out, size_t cap, const uint8_t *data, uint32_t len);
const char *ps4rf_kread_cb_status_name(uint32_t status);
const char *ps4rf_kread_run_status_name(int run_result);
const char *ps4rf_kread_bye_reason(int run_result);
int ps4rf_kread_event_status(int run_result);
jval *ps4rf_kread_event(const ps4rf_kread_info *info, int run_result,
                        const char *build_id, const char *label);

#endif /* PS4RF_KREAD_H */
