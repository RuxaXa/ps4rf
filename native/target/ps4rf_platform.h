/* PS4RF P4/W8 target agent -- platform interface.
 *
 * Everything that is genuinely platform specific lives behind these functions, so the
 * dispatch path (registry -> router -> stub provider -> resources -> evidence) is the
 * same code on the console and on the host:
 *
 *   * PS4 payload build : libPS4 sockets (initNetwork + the Sck/sceNet family),
 *                         sceKernelGetProcessTime, sceKernelUsleep, sysctl/getpid
 *                         pointers (all filled by the proven init chain; no kernel
 *                         primitive and no kexec is called).
 *   * host build        : BSD sockets, clock_gettime, nanosleep, /proc based telemetry.
 *
 * A value the platform cannot prove is reported as unavailable, which turns into
 * UNRESOLVED in the attestation -- never into an invented value.
 */
#ifndef PS4RF_PLATFORM_H
#define PS4RF_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#define PS4RF_PLATFORM_FIELD_MAX 96u

typedef enum {
    PS4RF_TF_UNRESOLVED = 0,
    PS4RF_TF_OK = 1
} ps4rf_fact_status;

/* W11.1 diagnostics: two userland access paths, measured values only. */
#define PS4RF_BOOTDIAG_MAX_BYTES 64
#define PS4RF_BOOTDIAG_METHOD_NAME 0
#define PS4RF_BOOTDIAG_METHOD_MIB 1
#define PS4RF_BOOTDIAG_MIB_KERN 1        /* CTL_KERN */
#define PS4RF_BOOTDIAG_MIB_BOOTTIME 21   /* KERN_BOOTTIME */

typedef struct ps4rf_bootdiag_method {
    int method;                 /* PS4RF_BOOTDIAG_METHOD_* */
    int size_query_attempted;
    int size_query_rc;          /* measured */
    int size_query_errno;       /* measured (0 when the ABI exposes no errno) */
    long long reported_size;    /* length the size query reported, -1 when it did not answer */
    int read_attempted;
    int read_rc;                /* measured */
    int read_errno;             /* measured */
    long long requested_size;   /* buffer size handed to the read */
    long long returned_size;    /* oldlen after the read, -1 when no read happened */
    unsigned raw_len;           /* bytes actually copied out (<= PS4RF_BOOTDIAG_MAX_BYTES) */
    unsigned char raw[PS4RF_BOOTDIAG_MAX_BYTES];
} ps4rf_bootdiag_method;

typedef struct ps4rf_bootdiag_result {
    ps4rf_bootdiag_method name_path;   /* sysctlbyname("kern.boottime", ...) */
    ps4rf_bootdiag_method mib_path;    /* sysctl({CTL_KERN, KERN_BOOTTIME}, 2, ...) */
    long long timeval_sizeof;          /* sizeof(struct timeval) as compiled for this build */
    int errno_observable;              /* 1 when the ABI exposes errno */
} ps4rf_bootdiag_result;

typedef struct {
    /* Nonce entropy: 1 = operating-system entropy, 0 = measured mix (the agent reports
     * which one it used in the READY attestation). */
    int nonce_source_os_entropy;
    /* Network */
    int (*net_connect)(const char *ip, unsigned port, int attempts);
    int (*net_send)(int fd, const void *buf, size_t len);
    int (*net_recv)(int fd, void *buf, size_t len);       /* >0 bytes, 0 = closed, -1 = retryable, -2 = fatal */
    void (*net_close)(int fd);
    /* Clock */
    uint64_t (*now_us)(void);
    void (*sleep_us)(unsigned us);
    /* Entropy */
    int (*random_bytes)(unsigned char *out, size_t len);
    /* Target facts (each returns PS4RF_TF_OK only with a measured value) */
    ps4rf_fact_status (*firmware)(char *out, size_t cap, size_t *len);
    ps4rf_fact_status (*model)(char *out, size_t cap, size_t *len);
    ps4rf_fact_status (*process_id)(long *out);
    ps4rf_fact_status (*boot_time_epoch)(long long *out);
    /* W11: the raw struct timeval behind KERN_BOOTTIME (sec + usec). Read-only, userland
     * sysctl only; the W11 boot id is derived from these two values. */
    ps4rf_fact_status (*boot_timeval)(long long *sec, long long *usec);
    /* W11: the console wall clock (seconds since the epoch), used only to refuse a boot instant
     * that lies in the future. Read-only userland call. */
    ps4rf_fact_status (*wall_sec)(long long *out);
    /* W11.1: instrumented read-only diagnostics over both userland sysctl wrappers. One size
     * query (oldval = NULL) and one bounded read (<= PS4RF_BOOTDIAG_MAX_BYTES) per path, with
     * return code, errno and returned length recorded as measured. Never writes. */
    ps4rf_fact_status (*boot_diag)(struct ps4rf_bootdiag_result *out);
    const char *identity;                                  /* compile-time platform name */
} ps4rf_platform;

const ps4rf_platform *ps4rf_platform_get(void);

/* W15R3: the debug-marker seam.
 *
 * One flat string, emitted through the platform's own debug-out (on the console that is the
 * kernel debug log the operator's passive capture reads). It is deliberately not a session
 * channel and not a frame: no request, no response, no sequencing. The callers pass fixed
 * literals only -- markers carry no key material, no trust object, no host input and no
 * measured value, so a log capture is never a secret channel. The host build prints them to
 * stderr when PS4RF_TRACE is set; the console build has no other output path by design. */
void ps4rf_trace_marker(const char *marker);

#endif /* PS4RF_PLATFORM_H */
