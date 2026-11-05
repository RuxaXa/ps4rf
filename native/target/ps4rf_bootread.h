/* PS4RF W11.2 -- fixed privileged boot identity read (the only privileged path in W11.2).
 *
 * Rules this file and its implementation keep (owner W11.2 brief):
 *   - exactly ONE privileged entry point: ps4rf_bootread_kpayload, reached through the SDK's
 *     kexec() exactly once per session (guard set BEFORE kexec, no retry, no loop over addresses)
 *   - exactly ONE fixed kernel data read region: kbase + 0x224C6C8, 16 bytes. The RVA and the
 *     length are compile-time constants inside the kernel section; the host supplies neither an
 *     address, nor an offset, nor a length, and cannot choose an alternative source.
 *   - kbase only by the proven W9 relation: LSTAR -> shape gate -> LSTAR - 0x1C0, cross-checked
 *     *inside the callback* against the SDK's own kernel base before a single byte is read.
 *   - read-only: one rdmsr(LSTAR), 16 fixed byte reads, writes into the caller's own info block.
 *     No kernel memory write, no arbitrary copy, no function pointer from the host, no syscall
 *     table change, no patch, no allocation, no locking, no persistent state.
 *   - fail closed: a bad LSTAR shape or a cross-check mismatch stops the callback with zero
 *     bytes read; the payload never forms a boot id (that is the host's job).
 *
 * Section split, enforced by the build gates (same discipline as W9): everything named
 * ps4rf_bootread_k* is the kernel section (the privileged instruction and the fixed read),
 * everything else is the user section (no kernel RVA constant, no absolute kernel pointer).
 */

#ifndef PS4RF_BOOTREAD_H
#define PS4RF_BOOTREAD_H

#include <stdint.h>

#include "ps4rf_protocol.h"   /* jval, for the sealed event body */

#define PS4RF_BOOTREAD_MAGIC_IN 0x57524B43u          /* "CKWR" caller marker            */
#define PS4RF_BOOTREAD_MAGIC_OUT 0x57524B44u         /* "DKWR" callback marker          */
#define PS4RF_BOOTREAD_GUARD 0x5053345246415431ull   /* "PS4RFBR1" struct end canary    */
#define PS4RF_BOOTREAD_READ_LEN 16u                  /* the one fixed read: 16 bytes    */

/* callback status (kernel section) */
#define PS4RF_BOOTREAD_CB_OK 0u
#define PS4RF_BOOTREAD_CB_ARGS 1u            /* args or info pointer missing               */
#define PS4RF_BOOTREAD_CB_MAGIC 2u           /* caller marker missing: wrong buffer        */
#define PS4RF_BOOTREAD_CB_LSTAR_SHAPE 3u     /* not canonical / page offset != 0x1C0       */
#define PS4RF_BOOTREAD_CB_KBASE_MISMATCH 4u  /* LSTAR base != SDK base: read nothing       */

/* run result (user section) */
#define PS4RF_BOOTREAD_RUN_OK 0
#define PS4RF_BOOTREAD_RUN_ALREADY 1          /* one-shot: a second call is refused         */
#define PS4RF_BOOTREAD_RUN_KEXEC_FAILED 2
#define PS4RF_BOOTREAD_RUN_CALLBACK 3         /* callback reported a failure status         */
#define PS4RF_BOOTREAD_RUN_RESULT_INVALID 4   /* magic_out / guard / length inconsistent    */
#define PS4RF_BOOTREAD_RUN_TIMEVAL_INVALID 5  /* tv_sec <= 0 / tv_usec < 0 / >= 1000000     */
#define PS4RF_BOOTREAD_RUN_IMPLAUSIBLE 6      /* boottime after the console wall clock      */

/* event run_status ids -- the same vocabulary the host re-derives (W11.1 ids) */
#define PS4RF_BOOTREAD_STATUS_OK 0
#define PS4RF_BOOTREAD_STATUS_READ_FAILED 1
#define PS4RF_BOOTREAD_STATUS_IMPLAUSIBLE 3

/* decode result codes (user section; the host re-derives the same status itself) */
#define PS4RF_BOOTREAD_DEC_OK 0
#define PS4RF_BOOTREAD_DEC_SEC 1              /* tv_sec <= 0                                */
#define PS4RF_BOOTREAD_DEC_USEC_NEG 2         /* tv_usec < 0                                */
#define PS4RF_BOOTREAD_DEC_USEC_RANGE 3       /* tv_usec >= 1000000                         */
#define PS4RF_BOOTREAD_DEC_FUTURE 4           /* boottime after the console wall clock      */
#define PS4RF_BOOTREAD_DEC_INCOMPLETE 5       /* no complete 16 byte read was made          */

/* validation status strings (host re-derives the same status from the raw bytes) */
#define PS4RF_BOOTREAD_VAL_OK "OK"
#define PS4RF_BOOTREAD_VAL_NOT_READ "NOT_READ"
#define PS4RF_BOOTREAD_VAL_SEC "TV_SEC_NONPOSITIVE"
#define PS4RF_BOOTREAD_VAL_USEC_NEG "TV_USEC_NEGATIVE"
#define PS4RF_BOOTREAD_VAL_USEC_RANGE "TV_USEC_OUT_OF_RANGE"
#define PS4RF_BOOTREAD_VAL_FUTURE "BOOT_TIME_AFTER_WALL_CLOCK"

typedef struct {
  uint32_t magic_in;         /* in  : PS4RF_BOOTREAD_MAGIC_IN                            */
  uint32_t cb_status;        /* out : callback status                                    */
  uint32_t read_count;       /* out : 1 when the fixed region was read, else 0           */
  uint32_t read_len;         /* out : PS4RF_BOOTREAD_READ_LEN when 16 bytes were copied  */
  int32_t kexec_rc;          /* out : kexec() return code                                */
  uint32_t reserved;         /* must stay 0; never host controlled                       */
  uint64_t lstar;            /* out : observed LSTAR                                     */
  uint64_t kbase_candidate;  /* out : lstar - 0x1C0                                      */
  uint64_t kbase_sdk;        /* in  : the SDK's own kernel base (set before kexec)       */
  uint64_t source_rva;       /* out : echo of the fixed compile-time source RVA          */
  uint64_t cross_check;      /* out : 1 = candidate == SDK base                          */
  uint8_t raw[PS4RF_BOOTREAD_READ_LEN];  /* out : the exact bytes read                   */
  uint64_t magic_out;        /* out : PS4RF_BOOTREAD_MAGIC_OUT                           */
  uint64_t guard;            /* out : PS4RF_BOOTREAD_GUARD                               */
} ps4rf_bootread_info;

/* The console's single privileged transition does not hand the payload its block directly: the
 * kernel builds a wrapper around the syscall-11 argument and passes a pointer to it, so the
 * caller's block sits in the *second* field (the W9 module carries the same first field, and its
 * live run proved the shape). Without this field the callback would read the kernel's syscall
 * handler as its result block and write a status word into kernel memory. */
struct ps4rf_bootread_args {
  void *syscall_handler;      /* first field of the kernel's syscall-11 wrapper: never touched */
  ps4rf_bootread_info *info;  /* the payload's own result block; no address, no length */
};
typedef struct ps4rf_bootread_args ps4rf_bootread_args;

typedef struct {
  long long tv_sec;
  long long tv_usec;
  long long wall_clock_sec;
  const char *validation;
} ps4rf_bootread_decoded;

/* kernel section */
int ps4rf_bootread_kpayload(void *td, struct ps4rf_bootread_args *args);
int ps4rf_bootread_k_lstar_ok(uint64_t lstar);

/* user section */
int ps4rf_bootread_run(ps4rf_bootread_info *info, long long wall_clock_sec);
int ps4rf_bootread_validate(const ps4rf_bootread_info *info);
int ps4rf_bootread_decode(const ps4rf_bootread_info *info, ps4rf_bootread_decoded *out,
                          long long wall_clock_sec);
const char *ps4rf_bootread_cb_status_name(uint32_t status);
const char *ps4rf_bootread_run_status_name(int run_result);
const char *ps4rf_bootread_bye_reason(int run_result);
int ps4rf_bootread_event_status(int run_result);
jval *ps4rf_bootread_event(const ps4rf_bootread_info *info, int run_result,
                           const ps4rf_bootread_decoded *decoded, long long wall_clock_sec,
                           const char *build_id, const char *label);

#endif /* PS4RF_BOOTREAD_H */
