/* PS4RF P4/W8 -- host platform layer (offline tests, host controller loopback).
 *
 * Same platform interface as the console payload: BSD sockets, POSIX clock, OS entropy.
 * The target facts stay UNRESOLVED unless the test environment provides the measured
 * values it wants to exercise (PS4RF_HOST_TELEMETRY_FW / _MODEL / _BOOT); nothing is
 * invented, and the host build never pretends to be the console.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ps4rf_platform.h"

/* W15R3: the host build's debug-marker seam. The console writes these to its kernel debug log;
 * the rehearsal writes them to stderr when PS4RF_TRACE is set so a test can assert the order of
 * the breadcrumbs (in particular that no marker of the privileged path precedes "B07 control
 * session established"). */
void ps4rf_trace_marker(const char *marker)
{
    if (marker == NULL || marker[0] == '\0') return;
    if (getenv("PS4RF_TRACE") == NULL) return;
    fprintf(stderr, "ps4rf-trace %s\n", marker);
    fflush(stderr);
}

static int host_connect(const char *ip, unsigned port, int attempts)
{
    int fd = -1;
    int i;
    for (i = 0; i < attempts; i++) {
        struct sockaddr_in addr;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
            close(fd);
            return -1;
        }
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            return fd;
        }
        close(fd);
        fd = -1;
        usleep(200000);
    }
    return -1;
}

static int host_send(int fd, const void *buf, size_t len)
{
    ssize_t rc = send(fd, buf, len, MSG_NOSIGNAL);
    if (rc > 0) return (int)rc;
    if (rc < 0 && (errno == EINTR || errno == EAGAIN)) return -1;
    if (rc == 0) return -2;
    return -2;
}

static int host_recv(int fd, void *buf, size_t len)
{
    ssize_t rc = recv(fd, buf, len, 0);
    if (rc > 0) return (int)rc;
    if (rc == 0) return 0;
    if (errno == EINTR || errno == EAGAIN) return -1;
    return -2;
}

static void host_close(int fd)
{
    close(fd);
}

static uint64_t host_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

static void host_sleep_us(unsigned us)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(us / 1000000u);
    ts.tv_nsec = (long)(us % 1000000u) * 1000l;
    nanosleep(&ts, NULL);
}

static int host_random(unsigned char *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t done = 0u;
    if (f == NULL) return -1;
    while (done < len) {
        size_t got = fread(out + done, 1u, len - done, f);
        if (got == 0u) {
            fclose(f);
            return -1;
        }
        done += got;
    }
    fclose(f);
    return 0;
}

static const char *env_or_null(const char *name)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0') return NULL;
    return v;
}

static ps4rf_fact_status host_field(const char *env_name, char *out, size_t cap, size_t *len)
{
    const char *v = env_or_null(env_name);
    if (v == NULL) {
        *len = 0u;
        if (cap > 0u) out[0] = '\0';
        return PS4RF_TF_UNRESOLVED;
    }
    *len = strlen(v);
    if (*len + 1u > cap) *len = cap - 1u;
    memcpy(out, v, *len);
    out[*len] = '\0';
    return PS4RF_TF_OK;
}

static ps4rf_fact_status host_firmware(char *out, size_t cap, size_t *len)
{
    return host_field("PS4RF_HOST_TELEMETRY_FW", out, cap, len);
}

static ps4rf_fact_status host_model(char *out, size_t cap, size_t *len)
{
    return host_field("PS4RF_HOST_TELEMETRY_MODEL", out, cap, len);
}

static ps4rf_fact_status host_process_id(long *out)
{
    *out = (long)getpid();
    return PS4RF_TF_OK;
}

static ps4rf_fact_status host_boot_timeval(long long *sec, long long *usec);

static ps4rf_fact_status host_boot_time(long long *out)
{
    long long usec = 0;
    return host_boot_timeval(out, &usec);
}

/* ---- W11.1 offline stand-in: scripted diagnostics over both sysctl paths -------------
 * PS4RF_HOST_BOOTDIAG = "name=<rc>:<errno>:<reported>:<returned>:<hex>;mib=<rc>:<errno>:<reported>:<returned>:<hex>"
 * Unset: both paths answer with the pinned capture boot timeval (16 bytes, the honest default).
 * The hex is capped at PS4RF_BOOTDIAG_MAX_BYTES (64) characters of payload, as on the console. */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void host_diag_parse(ps4rf_bootdiag_method *out, int method, const char *spec)
{
    const char *p = spec;
    char *end = NULL;
    memset(out, 0, sizeof(*out));
    if (p != NULL && strncmp(p, "name=", 5) == 0) p += 5;   /* documented spec prefixes */
    if (p != NULL && strncmp(p, "mib=", 4) == 0) p += 4;
    out->method = method;
    out->reported_size = -1;
    out->returned_size = -1;
    out->size_query_attempted = 1;
    if (p == NULL) return;
    out->size_query_rc = (int)strtol(p, &end, 10);
    p = (end != NULL && *end == ':') ? end + 1 : NULL;
    if (p != NULL) { out->size_query_errno = (int)strtol(p, &end, 10); p = (end && *end == ':') ? end + 1 : NULL; }
    if (p != NULL) { out->reported_size = strtoll(p, &end, 10); p = (end && *end == ':') ? end + 1 : NULL; }
    if (p != NULL) {
        out->read_attempted = 1;
        out->read_rc = out->size_query_rc;
        out->read_errno = out->size_query_errno;
        out->returned_size = strtoll(p, &end, 10);
        out->requested_size = PS4RF_BOOTDIAG_MAX_BYTES;
        p = (end != NULL && *end == ':') ? end + 1 : NULL;
    }
    if (p != NULL && out->size_query_rc == 0) {
        unsigned n = 0u;
        while (p[0] != '\0' && p[1] != '\0' && n < PS4RF_BOOTDIAG_MAX_BYTES) {
            int hi = hex_nibble(p[0]);
            int lo = hex_nibble(p[1]);
            if (hi < 0 || lo < 0) break;
            out->raw[n++] = (unsigned char)((hi << 4) | lo);
            p += 2;
        }
        out->raw_len = n;
        if (out->returned_size < 0 || (long long)n < out->returned_size) {
            out->returned_size = (long long)n;
        }
    }
}

static ps4rf_fact_status host_boot_diag(ps4rf_bootdiag_result *out)
{
    static const char default_hex[] = "f0dcaf6a00000000e0220d0000000000";
    const char *env = env_or_null("PS4RF_HOST_BOOTDIAG");
    char name_spec[256];
    char mib_spec[256];
    if (out == NULL) return PS4RF_TF_UNRESOLVED;
    memset(out, 0, sizeof(*out));
    out->timeval_sizeof = (long long)sizeof(struct timeval);
    out->errno_observable = 1;
    if (env == NULL) {
        snprintf(name_spec, sizeof(name_spec), "0:0:16:16:%s", default_hex);
        snprintf(mib_spec, sizeof(mib_spec), "0:0:16:16:%s", default_hex);
    } else {
        const char *semi = strchr(env, ';');
        size_t n = (semi != NULL) ? (size_t)(semi - env) : strlen(env);
        if (n >= sizeof(name_spec)) n = sizeof(name_spec) - 1u;
        memcpy(name_spec, env, n);
        name_spec[n] = '\0';
        if (semi == NULL) {
            mib_spec[0] = '\0';
        } else {
            size_t m = strlen(semi + 1);
            if (m >= sizeof(mib_spec)) m = sizeof(mib_spec) - 1u;
            memcpy(mib_spec, semi + 1, m);      /* no overlapping snprintf: explicit copy */
            mib_spec[m] = '\0';
        }
    }
    host_diag_parse(&out->name_path, PS4RF_BOOTDIAG_METHOD_NAME, name_spec);
    host_diag_parse(&out->mib_path, PS4RF_BOOTDIAG_METHOD_MIB, mib_spec);
    /* optional: make the source drift between calls, so the stability gate can be exercised
     * offline (models a counter-shaped source such as time_second) */
    {
        const char *drift = env_or_null("PS4RF_HOST_BOOTDIAG_DRIFT_USEC");
        static long long calls = 0;
        if (drift != NULL) {
            long long step = strtoll(drift, NULL, 10);
            long long delta;
            ps4rf_bootdiag_method *paths[2];
            calls++;
            delta = step * calls;
            paths[0] = &out->name_path;
            paths[1] = &out->mib_path;
            for (int i = 0; i < 2; i++) {
                ps4rf_bootdiag_method *m = paths[i];
                unsigned long long usec;
                if (m->raw_len < 16u) continue;
                usec = 0ull;
                for (int b = 7; b >= 0; b--) usec = (usec << 8) | (unsigned long long)m->raw[8 + b];
                usec = (unsigned long long)((long long)usec + delta);
                for (int b = 0; b < 8; b++) m->raw[8 + b] = (unsigned char)(usec >> (8 * b));
            }
        }
    }
    return PS4RF_TF_OK;
}

/* W11: host build uses the real host clock as the "console wall clock". */
static ps4rf_fact_status host_wall_sec(long long *out)
{
    time_t now;
    if (out == NULL) return PS4RF_TF_UNRESOLVED;
    now = time(NULL);
    if (now <= (time_t)0) return PS4RF_TF_UNRESOLVED;
    *out = (long long)now;
    return PS4RF_TF_OK;
}

/* W11 offline stand-in for the read-only KERN_BOOTTIME sysctl. The console value comes from
 * PS4RF_HOST_BOOTTIME as "<sec>.<usec>" -- the honest stand-in used by the host build in place
 * of the console's sysctl. An optional PS4RF_HOST_BOOTTIME_DRIFT_USEC makes the second read
 * differ so that the BOOT_SOURCE_NOT_STABLE gate can be exercised offline. Without the variable
 * the source is UNRESOLVED (fail closed: never a guessed boot time). */
static ps4rf_fact_status host_boot_timeval(long long *sec, long long *usec)
{
    static long long drift_sum = 0;         /* models a drifting source (time_second style) */
    const char *v = env_or_null("PS4RF_HOST_BOOTTIME");
    const char *drift = env_or_null("PS4RF_HOST_BOOTTIME_DRIFT_USEC");
    const char *dot;
    if (sec == NULL || usec == NULL || v == NULL) return PS4RF_TF_UNRESOLVED;
    dot = strchr(v, '.');
    if (dot == NULL) return PS4RF_TF_UNRESOLVED;
    *sec = strtoll(v, NULL, 10);
    *usec = strtoll(dot + 1, NULL, 10);
    if (drift != NULL) {
        /* each read moves on by the given amount: two reads in one session differ, exactly like
         * a counter-shaped (wrong) source would. Without the variable the source is stable. */
        drift_sum += strtoll(drift, NULL, 10);
        *usec += drift_sum;
    }
    return PS4RF_TF_OK;
}

static const ps4rf_platform HOST_PLATFORM = {
    1,                       /* entropy source present */
    host_connect,
    host_send,
    host_recv,
    host_close,
    host_now_us,
    host_sleep_us,
    host_random,
    host_firmware,
    host_model,
    host_process_id,
    host_boot_time,
    host_boot_timeval,
    host_wall_sec,
    host_boot_diag,
    "host-test"
};

const ps4rf_platform *ps4rf_platform_get(void)
{
    return &HOST_PLATFORM;
}
