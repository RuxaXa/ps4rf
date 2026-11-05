/* PS4RF W11 / W11.1 -- read-only userland boot binding and diagnostics.
 *
 * Scope (enforced by the build gates, not by comments):
 *   * no privileged instruction, no kexec, no kernel address, no RVA, no kernel write
 *   * only the two userland sysctl wrappers are used, always read-only (newval = NULL, newlen = 0)
 *   * the size query (oldval = NULL) always runs first; the bounded read is capped at
 *     PS4RF_BOOTDIAG_MAX_BYTES (64) and never interprets bytes beyond the returned length
 *   * no digest is computed on the console: the canonical boot id is derived on the host side
 *     (tools/profiles/bootid.py) from the raw values reported here
 *
 * Contract: a boot identity needs a *complete* ``struct timeval`` (16 bytes on this ABI, proven by
 * static assert and by the SDK layout). A partial answer (e.g. 8 bytes) is reported as
 * BOOT_SOURCE_PARTIAL and never accepted, and the 8 bytes are never guessed to be tv_sec.
 */
#ifndef PS4RF_BOOT_H
#define PS4RF_BOOT_H

#include <stddef.h>

#include "ps4rf_platform.h"
#include "ps4rf_protocol.h"   /* jval, for the event body */

#define PS4RF_BOOT_SOURCE "sysctl:kern.boottime"
#define PS4RF_BOOT_SOURCE_KIND "userland-sysctl-readonly"
#define PS4RF_BOOT_PAUSE_US 60000u            /* bounded pause between the two readings */
#define PS4RF_BOOT_TIMEVAL_BYTES 16           /* full struct timeval (abi-proven) */

/* run status: 0 means a measured, stable, plausible complete timeval */
#define PS4RF_BOOT_RUN_OK 0
#define PS4RF_BOOT_RUN_READ_FAILED 1
#define PS4RF_BOOT_RUN_NOT_STABLE 2
#define PS4RF_BOOT_RUN_IMPLAUSIBLE 3
#define PS4RF_BOOT_RUN_PARTIAL 4
#define PS4RF_BOOT_RUN_CONFLICT 5

/* per method classification (machine readable, measured values only) */
#define PS4RF_BOOT_SYSCTL_SUCCESS 0
#define PS4RF_BOOT_SYSCTL_NAME_NOT_FOUND 1
#define PS4RF_BOOT_SYSCTL_MIB_NOT_FOUND 2
#define PS4RF_BOOT_SYSCTL_PERMISSION 3
#define PS4RF_BOOT_SYSCTL_INVALID_ARGUMENT 4
#define PS4RF_BOOT_SYSCTL_SIZE_QUERY_FAILED 5
#define PS4RF_BOOT_SYSCTL_READ_FAILED 6
#define PS4RF_BOOT_SYSCTL_SHORT_RESULT 7
#define PS4RF_BOOT_SYSCTL_MALFORMED_RESULT 8

/* errno values are only used to classify *measured* errno codes, never guessed from prose */
#define PS4RF_BOOT_ERRNO_EPERM 1
#define PS4RF_BOOT_ERRNO_ENOENT 2
#define PS4RF_BOOT_ERRNO_EACCES 13
#define PS4RF_BOOT_ERRNO_EINVAL 22

typedef struct ps4rf_boot_info {
    int run_status;
    ps4rf_bootdiag_result diag;      /* raw measured diagnostics of both paths */
    int name_class;                  /* classification of the sysctlbyname path */
    int mib_class;                   /* classification of the MIB path */
    int preferred_path;              /* PS4RF_BOOTDIAG_METHOD_NAME / _MIB / -1 = both or none */
    int both_identical;              /* 1 when both paths delivered identical complete bytes */
    long long sec1;                  /* first reading (preferred path) */
    long long usec1;
    long long sec2;                  /* second reading after the bounded pause */
    long long usec2;
    int reads_identical;
    long long console_wall_sec;
    int wall_clock_ok;
    int boottime_after_wall_clock;
    int plausible;
    unsigned pause_us;
} ps4rf_boot_info;

/* Runs the W11.1 diagnostics, evaluates the contract and (only with a complete timeval) the
 * stability reading. Read-only throughout. */
int ps4rf_boot_collect(ps4rf_boot_info *info);

/* Human readable names (also used as the BYE reason on failure). */
const char *ps4rf_boot_status_name(int run_status);
const char *ps4rf_boot_class_name(int classification);
const char *ps4rf_boot_method_name(int method);

/* The sealed EVENT body for the session (event = "boot.binding"). */
jval *ps4rf_boot_event(const ps4rf_boot_info *info, const char *build_id, const char *label);

#endif /* PS4RF_BOOT_H */
