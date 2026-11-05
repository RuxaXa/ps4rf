/* PS4RF P4/W8 -- PS4 (Orbis) platform layer for the target agent.
 *
 * What this file does and does not do:
 *
 *  * it calls the proven libPS4 init chain (initKernel / initLibc / initNetwork) so the
 *    SDK function pointers are filled before any of them is used
 *  * it uses the socket API the live-proven userland payloads used, including the
 *    FreeBSD-style `sin_len` field
 *  * it reads the target identity through legitimate read-only userland APIs
 *    (sysctlbyname, getpid) and reports UNRESOLVED when one of them does not answer
 *  * it never calls a kernel primitive, never touches CR0, never resolves a kernel base,
 *    never uses kexec and never writes anything to the console
 *
 * No privileged symbol is referenced from here, so the linker never pulls the objects that
 * carry privileged helpers (see native/target/build_ps4.sh, which proves that on the
 * artefact).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ps4.h"

#include "ps4rf_platform.h"

#define PS4RF_URANDOM_PATH "/dev/urandom"

/* ------------------------------------------------------------------ debug markers (W15R3) */

/* The SDK's own debug-out facility -- exactly the call its debug.h macro makes (syscall 601,
 * sub-command 7), issued through the SDK's syscall entry so no libc pointer, no format string and
 * no console state is involved. Fixed literals only; see ps4rf_platform.h. */
void ps4rf_trace_marker(const char *marker)
{
    if (marker == NULL || marker[0] == '\0') return;
    (void)syscall(601, 7, marker, 0);
}

/* A marker with one plain decimal value appended (the dial's return code and errno). Digits are
 * built by hand: the marker path must not depend on a printf pointer being filled. */
static void ps4_trace_number(const char *prefix, long value)
{
    char buf[64];
    size_t at = 0u;
    unsigned long mag;
    char digits[24];
    size_t n = 0u;

    if (prefix == NULL) return;
    while (prefix[at] != '\0' && at + 3u < sizeof(buf)) {
        buf[at] = prefix[at];
        at++;
    }
    if (value < 0) {
        if (at + 1u < sizeof(buf)) buf[at++] = '-';
        mag = (unsigned long)(-(value + 1)) + 1ul;
    } else {
        mag = (unsigned long)value;
    }
    do {
        digits[n++] = (char)('0' + (int)(mag % 10ul));
        mag /= 10ul;
    } while (mag != 0ul && n < sizeof(digits));
    while (n > 0u && at + 1u < sizeof(buf)) buf[at++] = digits[--n];
    buf[at] = '\0';
    ps4rf_trace_marker(buf);
}

/* ------------------------------------------------------------------ networking */

static int ps4_connect(const char *ip, unsigned port, int attempts)
{
    int i;
    for (i = 0; i < attempts; i++) {
        struct sockaddr_in sk;
        int s;
        int rc;
        memset(&sk, 0, sizeof(sk));
        if (sceNetInetPton(AF_INET, ip, &sk.sin_addr) != 1) return -1;
        sk.sin_len = sizeof(sk);
        sk.sin_family = AF_INET;
        sk.sin_port = sceNetHtons((uint16_t)port);
        s = sceNetSocket("ps4rfd", AF_INET, SOCK_STREAM, 0);
        if (s >= 0) {
            ps4rf_trace_marker("B04 socket created");
            ps4rf_trace_marker("B05 connect attempt");
            rc = sceNetConnect(s, (struct sockaddr *)&sk, sizeof(sk));
            ps4_trace_number("B06 connect rc ", (long)rc);
            if (rc == 0) return s;
            if (sceNetErrnoLoc != NULL) ps4_trace_number("B06 errno ", (long)*sceNetErrnoLoc());
            sceNetSocketClose(s);
        } else {
            ps4rf_trace_marker("B04 socket failed");
        }
        sceKernelUsleep(200000u);
    }
    return -1;
}

/* sceNetSend/sceNetRecv return a negative SCE error code on failure; the two retryable
 * ones are EAGAIN and EINTR (SCE_NET_ERROR_* base 0x804101xx). Everything else is fatal
 * for this session. */
#define PS4RF_NET_EAGAIN 0x80410123
#define PS4RF_NET_EINTR 0x80410104

static int ps4_send(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0u;
    while (sent < len) {
        int k = sceNetSend(fd, (void *)(p + sent), len - sent, 0);
        if (k > 0) {
            sent += (size_t)k;
            continue;
        }
        if (k == 0 || (unsigned)k == PS4RF_NET_EAGAIN || (unsigned)k == PS4RF_NET_EINTR) return -1;
        return -2;
    }
    return (int)sent;
}

static int ps4_recv(int fd, void *buf, size_t len)
{
    int k = sceNetRecv(fd, buf, len, 0);
    if (k > 0) return k;
    if (k == 0) return 0;
    if ((unsigned)k == PS4RF_NET_EAGAIN || (unsigned)k == PS4RF_NET_EINTR) return -1;
    return -2;
}

static void ps4_close(int fd)
{
    if (fd >= 0) sceNetSocketClose(fd);
}

/* ----------------------------------------------------------------------- clock */

static uint64_t ps4_now_us(void)
{
    return (uint64_t)sceKernelGetProcessTime();
}

static void ps4_sleep_us(unsigned us)
{
    sceKernelUsleep(us);
}

/* --------------------------------------------------------------------- entropy */

static int ps4_random(unsigned char *out, size_t len)
{
    int fd = open(PS4RF_URANDOM_PATH, O_RDONLY, 0);
    size_t got = 0u;
    if (fd >= 0) {
        while (got < len) {
            int k = read(fd, out + got, len - got);
            if (k <= 0) break;
            got += (size_t)k;
        }
        close(fd);
        if (got == len) return 0;
    }
    /* No OS entropy source: a measured mix (process time, pid, boot time, a counter).
     * The agent reports this in the READY attestation as `nonce_source` -- it is never
     * presented as operating-system entropy. */
    {
        unsigned long long mix = ps4_now_us();
        long pid = 0;
        long long boot = 0;
        size_t l = sizeof(boot);
        unsigned i;
        getpid();
        mix ^= (unsigned long long)(pid << 17);
        if (sysctlbyname((char *)"kern.boottime", (char *)&boot, &l, NULL, 0) == 0 && l >= (size_t)sizeof(int64_t)) {
            mix ^= (unsigned long long)boot * 0x9E3779B97F4A7C15ull;
        }
        for (i = 0u; i < len; i++) {
            mix ^= mix << 13; mix ^= mix >> 7; mix ^= mix << 17;
            out[i] = (unsigned char)(mix >> ((i % 8u) * 8u));
        }
    }
    return -1;
}

/* ------------------------------------------------------------------- telemetry */

static ps4rf_fact_status ps4_sysctl_string(const char *name, char *out, size_t cap, size_t *len,
                                           const char **source_used)
{
    size_t l = cap > 1u ? cap - 1u : 0u;
    if (sysctlbyname((char *)name, out, &l, NULL, 0) != 0) {
        out[0] = '\0';
        *len = 0u;
        return PS4RF_TF_UNRESOLVED;
    }
    out[l < cap ? l : cap - 1u] = '\0';
    *len = strlen(out);
    if (*len == 0u) return PS4RF_TF_UNRESOLVED;
    if (source_used != NULL) *source_used = name;
    return PS4RF_TF_OK;
}

/* Firmware identity without touching anything privileged: the first sysctl name that
 * answers wins, and the name is part of the attestation. */
static ps4rf_fact_status ps4_firmware(char *out, size_t cap, size_t *len)
{
    static const char names[3][24] = {"kern.osrelease", "kern.version", "kern.sdk_version"};
    unsigned i;
    for (i = 0u; i < 3u; i++) {
        char buf[PS4RF_PLATFORM_FIELD_MAX];
        size_t l = 0u;
        if (ps4_sysctl_string(names[i], buf, sizeof(buf), &l, NULL) == PS4RF_TF_OK) {
            if (l + 1u > cap) l = cap - 1u;
            memcpy(out, buf, l);
            out[l] = '\0';
            *len = l;
            return PS4RF_TF_OK;
        }
    }
    out[0] = '\0';
    *len = 0u;
    return PS4RF_TF_UNRESOLVED;
}

static ps4rf_fact_status ps4_model(char *out, size_t cap, size_t *len)
{
    return ps4_sysctl_string("hw.model", out, cap, len, NULL);
}

static ps4rf_fact_status ps4_process_id(long *out)
{
    *out = (long)getpid();
    return PS4RF_TF_OK;
}

/* W11: the same read-only sysctl, but keeping both timeval fields. This is the source of the
 * boot binding; nothing privileged is involved and no kernel address is touched. */
static ps4rf_fact_status ps4_boot_timeval(long long *sec, long long *usec)
{
    int64_t tv[2];          /* struct timeval: seconds, microseconds */
    size_t l = sizeof(tv);
    if (sec == NULL || usec == NULL) return PS4RF_TF_UNRESOLVED;
    if (sysctlbyname((char *)"kern.boottime", (char *)tv, &l, NULL, 0) != 0) {
        return PS4RF_TF_UNRESOLVED;
    }
    if (l < (size_t)(2 * sizeof(int64_t))) return PS4RF_TF_UNRESOLVED;   /* no partial truth */
    *sec = (long long)tv[0];
    *usec = (long long)tv[1];
    return PS4RF_TF_OK;
}

static ps4rf_fact_status ps4_boot_time(long long *out)
{
    long long usec = 0;
    return ps4_boot_timeval(out, &usec);
}

/* ---- W11.1: instrumented read-only diagnostics over both userland sysctl wrappers ---- */

/* The userland ABI the diagnostics rely on (libPS4 types.h / kernel.h):
 *   time_t tv_sec (int64_t) + suseconds_t tv_usec (long, 8 bytes) -> struct timeval == 16 bytes
 * The static asserts make a target where that is not true a compile error, so the contract can
 * never silently drift (W11.1 requirement 5). */
typedef struct { int64_t tv_sec; int64_t tv_usec; } ps4rf_bootdiag_timeval_abi;
typedef char ps4rf_bootdiag_timeval_is_16[(sizeof(ps4rf_bootdiag_timeval_abi) == 16) ? 1 : -1];
typedef char ps4rf_bootdiag_timeval_is_aligned[(__alignof__(ps4rf_bootdiag_timeval_abi) == 8) ? 1 : -1];
typedef char ps4rf_bootdiag_time_t_is_8[(sizeof(int64_t) == 8) ? 1 : -1];

static int ps4_diag_errno_observable;

static int ps4_diag_errno_read(void)
{
    int *slot;
    if (__error == NULL) { ps4_diag_errno_observable = 0; return 0; }
    slot = __error();
    if (slot == NULL) { ps4_diag_errno_observable = 0; return 0; }
    ps4_diag_errno_observable = 1;
    return *slot;
}

static void ps4_diag_errno_reset(void)
{
    int *slot;
    if (__error == NULL) return;
    slot = __error();
    if (slot != NULL) *slot = 0;
}

/* One path: size query (oldval = NULL) first, then a bounded read of at most
 * PS4RF_BOOTDIAG_MAX_BYTES. Both calls are read-only (newval = NULL, newlen = 0). */
static void ps4_diag_one(ps4rf_bootdiag_method *out, int method)
{
    int mib[2];
    size_t len;
    int rc;
    memset(out, 0, sizeof(*out));
    out->method = method;
    out->reported_size = -1;
    out->returned_size = -1;
    mib[0] = PS4RF_BOOTDIAG_MIB_KERN;
    mib[1] = PS4RF_BOOTDIAG_MIB_BOOTTIME;

    len = 0u;
    ps4_diag_errno_reset();
    if (method == PS4RF_BOOTDIAG_METHOD_NAME) {
        rc = sysctlbyname((char *)"kern.boottime", NULL, &len, NULL, 0);
    } else {
        rc = sysctl(mib, 2u, NULL, &len, NULL, 0);
    }
    out->size_query_attempted = 1;
    out->size_query_rc = rc;
    out->size_query_errno = ps4_diag_errno_read();
    if (rc == 0) {
        out->reported_size = (long long)len;
        return;                     /* the caller decides when to read; the read is a second step */
    }
}

static void ps4_diag_read(ps4rf_bootdiag_method *out)
{
    unsigned char buf[PS4RF_BOOTDIAG_MAX_BYTES];
    int mib[2];
    size_t want;
    int rc;
    if (out == NULL || !out->size_query_attempted || out->size_query_rc != 0) return;
    mib[0] = PS4RF_BOOTDIAG_MIB_KERN;
    mib[1] = PS4RF_BOOTDIAG_MIB_BOOTTIME;
    want = (out->reported_size > 0 && out->reported_size <= (long long)PS4RF_BOOTDIAG_MAX_BYTES)
               ? (size_t)out->reported_size
               : (size_t)PS4RF_BOOTDIAG_MAX_BYTES;
    memset(buf, 0, sizeof(buf));
    out->requested_size = (long long)want;
    ps4_diag_errno_reset();
    if (out->method == PS4RF_BOOTDIAG_METHOD_NAME) {
        rc = sysctlbyname((char *)"kern.boottime", (char *)buf, &want, NULL, 0);
    } else {
        rc = sysctl(mib, 2u, (char *)buf, &want, NULL, 0);
    }
    out->read_attempted = 1;
    out->read_rc = rc;
    out->read_errno = ps4_diag_errno_read();
    out->returned_size = (long long)want;
    if (rc == 0) {
        unsigned n = (want <= (size_t)PS4RF_BOOTDIAG_MAX_BYTES) ? (unsigned)want
                                                                 : (unsigned)PS4RF_BOOTDIAG_MAX_BYTES;
        memcpy(out->raw, buf, n);
        out->raw_len = n;
    }
}

static ps4rf_fact_status ps4_boot_diag(ps4rf_bootdiag_result *out)
{
    if (out == NULL) return PS4RF_TF_UNRESOLVED;
    memset(out, 0, sizeof(*out));
    out->timeval_sizeof = (long long)sizeof(ps4rf_bootdiag_timeval_abi);
    out->errno_observable = 1;
    ps4_diag_one(&out->name_path, PS4RF_BOOTDIAG_METHOD_NAME);
    ps4_diag_read(&out->name_path);
    ps4_diag_one(&out->mib_path, PS4RF_BOOTDIAG_METHOD_MIB);
    ps4_diag_read(&out->mib_path);
    out->errno_observable = ps4_diag_errno_observable;
    return PS4RF_TF_OK;
}

/* W11: the console wall clock, read through the SDK's userland call. Nothing privileged. */
static ps4rf_fact_status ps4_wall_sec(long long *out)
{
    SceKernelTimeval tv;
    if (out == NULL) return PS4RF_TF_UNRESOLVED;
    memset(&tv, 0, sizeof(tv));
    if (sceKernelGettimeofday(&tv) != 0) return PS4RF_TF_UNRESOLVED;
    *out = (long long)tv.tv_sec;
    return (tv.tv_sec > 0) ? PS4RF_TF_OK : PS4RF_TF_UNRESOLVED;
}

/* ------------------------------------------------------------------- platform */

/* Zero-initialised on purpose: a struct initialiser full of function pointers would emit
 * ELF relocations (R_X86_64_RELATIVE in .data.rel.local), and the loader applies none. The
 * pointers are attached once at runtime instead. */
static ps4rf_platform PS4_PLATFORM;

static void ps4_platform_bind(void)
{
    static int bound = 0;
    if (bound) return;
    PS4_PLATFORM.nonce_source_os_entropy = 1;   /* downgraded by the probe if needed */
    PS4_PLATFORM.net_connect = ps4_connect;
    PS4_PLATFORM.net_send = ps4_send;
    PS4_PLATFORM.net_recv = ps4_recv;
    PS4_PLATFORM.net_close = ps4_close;
    PS4_PLATFORM.now_us = ps4_now_us;
    PS4_PLATFORM.sleep_us = ps4_sleep_us;
    PS4_PLATFORM.random_bytes = ps4_random;
    PS4_PLATFORM.firmware = ps4_firmware;
    PS4_PLATFORM.model = ps4_model;
    PS4_PLATFORM.process_id = ps4_process_id;
    PS4_PLATFORM.boot_time_epoch = ps4_boot_time;
    PS4_PLATFORM.boot_timeval = ps4_boot_timeval;
    PS4_PLATFORM.wall_sec = ps4_wall_sec;
    PS4_PLATFORM.boot_diag = ps4_boot_diag;
    PS4_PLATFORM.identity = "orbis";
    bound = 1;
}

/* Called once from _main before the session starts so the entropy source is known before
 * the attestation is built. */
void ps4rf_platform_probe(void)
{
    unsigned char probe[16];
    ps4_platform_bind();
    PS4_PLATFORM.nonce_source_os_entropy = (ps4_random(probe, sizeof(probe)) == 0) ? 1 : 0;
}

const ps4rf_platform *ps4rf_platform_get(void)
{
    ps4_platform_bind();
    return &PS4_PLATFORM;
}
