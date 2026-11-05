/* PS4RF W11.1 -- read-only userland boot binding and diagnostics implementation.
 *
 * There is no kernel access in this file: no kexec, no rdmsr, no kernel address, no RVA and no
 * allocation. The boot instant comes exclusively from the platform layer's instrumented read-only
 * KERN_BOOTTIME diagnostics (on the console: the two libPS4 sysctl wrappers, resolved from
 * libkernel). Every classification below is computed from *measured* return codes, errno values
 * and returned lengths -- never from a description.
 */

#include "ps4rf_boot.h"
#include "ps4rf_libc.h"
#include "sha256.h"      /* the project's own, already-tested SHA-256 (native/src) */

/* ------------------------------------------------------------------ helpers */

/* decimal rendering without printf formatting (the target libc has no varargs use here) */
static void dec_ll(char *out, size_t cap, long long value)
{
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

static void hex_bytes(char *out, size_t cap, const unsigned char *data, unsigned len)
{
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    size_t o = 0u;
    for (i = 0u; i < len && o + 2u < cap; i++) {
        out[o++] = digits[(data[i] >> 4) & 0xfu];
        out[o++] = digits[data[i] & 0xfu];
    }
    out[o] = '\0';
}

static long long le64(const unsigned char *p)
{
    unsigned long long v = 0ull;
    int i;
    for (i = 7; i >= 0; i--) v = (v << 8) | (unsigned long long)p[i];
    return (long long)v;
}

/* ------------------------------------------------------------------ classification */

/* measured values only: return code, errno, returned length, then the bytes themselves */
static int classify(const ps4rf_bootdiag_method *m)
{
    if (!m->size_query_attempted) return PS4RF_BOOT_SYSCTL_SIZE_QUERY_FAILED;
    if (m->size_query_rc != 0) {
        int e = m->size_query_errno;
        if (e == PS4RF_BOOT_ERRNO_ENOENT) {
            return (m->method == PS4RF_BOOTDIAG_METHOD_NAME) ? PS4RF_BOOT_SYSCTL_NAME_NOT_FOUND
                                                             : PS4RF_BOOT_SYSCTL_MIB_NOT_FOUND;
        }
        if (e == PS4RF_BOOT_ERRNO_EPERM || e == PS4RF_BOOT_ERRNO_EACCES) return PS4RF_BOOT_SYSCTL_PERMISSION;
        if (e == PS4RF_BOOT_ERRNO_EINVAL) return PS4RF_BOOT_SYSCTL_INVALID_ARGUMENT;
        return PS4RF_BOOT_SYSCTL_SIZE_QUERY_FAILED;
    }
    if (!m->read_attempted) return PS4RF_BOOT_SYSCTL_SIZE_QUERY_FAILED;
    if (m->read_rc != 0) {
        int e = m->read_errno;
        if (e == PS4RF_BOOT_ERRNO_ENOENT) {
            return (m->method == PS4RF_BOOTDIAG_METHOD_NAME) ? PS4RF_BOOT_SYSCTL_NAME_NOT_FOUND
                                                             : PS4RF_BOOT_SYSCTL_MIB_NOT_FOUND;
        }
        if (e == PS4RF_BOOT_ERRNO_EPERM || e == PS4RF_BOOT_ERRNO_EACCES) return PS4RF_BOOT_SYSCTL_PERMISSION;
        if (e == PS4RF_BOOT_ERRNO_EINVAL) return PS4RF_BOOT_SYSCTL_INVALID_ARGUMENT;
        return PS4RF_BOOT_SYSCTL_READ_FAILED;
    }
    if (m->returned_size < (long long)PS4RF_BOOT_TIMEVAL_BYTES) return PS4RF_BOOT_SYSCTL_SHORT_RESULT;
    if (m->raw_len < PS4RF_BOOT_TIMEVAL_BYTES) return PS4RF_BOOT_SYSCTL_SHORT_RESULT;
    {
        long long sec = le64(m->raw);
        long long usec = le64(m->raw + 8);
        if (sec <= 0 || usec < 0 || usec >= 1000000) return PS4RF_BOOT_SYSCTL_MALFORMED_RESULT;
    }
    return PS4RF_BOOT_SYSCTL_SUCCESS;
}

static int bytes_equal16(const unsigned char *a, const unsigned char *b)
{
    unsigned i;
    for (i = 0u; i < PS4RF_BOOT_TIMEVAL_BYTES; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ collection */

int ps4rf_boot_collect(ps4rf_boot_info *info)
{
    const ps4rf_platform *p;
    int have_name;
    int have_mib;
    long long wall = -1;
    if (info == NULL) return PS4RF_BOOT_RUN_READ_FAILED;
    memset(info, 0, sizeof(*info));
    info->pause_us = PS4RF_BOOT_PAUSE_US;
    info->preferred_path = -1;
    p = ps4rf_platform_get();
    if (p == NULL || p->boot_diag == NULL) {
        info->run_status = PS4RF_BOOT_RUN_READ_FAILED;
        return info->run_status;
    }

    /* step 1: instrumented diagnostics (size query first, then a bounded read, per path) */
    memset(&info->diag, 0, sizeof(info->diag));
    (void)p->boot_diag(&info->diag);
    info->name_class = classify(&info->diag.name_path);
    info->mib_class = classify(&info->diag.mib_path);
    have_name = (info->name_class == PS4RF_BOOT_SYSCTL_SUCCESS);
    have_mib = (info->mib_class == PS4RF_BOOT_SYSCTL_SUCCESS);

    if (have_name && have_mib) {
        info->both_identical = bytes_equal16(info->diag.name_path.raw, info->diag.mib_path.raw);
        if (!info->both_identical) {
            info->run_status = PS4RF_BOOT_RUN_CONFLICT;
            return info->run_status;
        }
        info->preferred_path = PS4RF_BOOTDIAG_METHOD_NAME;   /* identical; name path recorded */
    } else if (have_name || have_mib) {
        /* Exactly one path delivered a complete timeval. That is an acceptable single source
         * (W11.1 section 9), but only when the other path did not answer with bytes at all: a
         * sibling that returns bytes which are short or not a valid timeval contradicts the
         * working path, so nothing is bound and the run is reported as a conflict. */
        const ps4rf_bootdiag_method *other =
            have_name ? &info->diag.mib_path : &info->diag.name_path;
        int other_class = have_name ? info->mib_class : info->name_class;
        if (other->raw_len > 0u &&
            (other_class == PS4RF_BOOT_SYSCTL_SHORT_RESULT ||
             other_class == PS4RF_BOOT_SYSCTL_MALFORMED_RESULT)) {
            info->preferred_path = -1;
            info->run_status = PS4RF_BOOT_RUN_CONFLICT;
            return info->run_status;
        }
        info->preferred_path = have_name ? PS4RF_BOOTDIAG_METHOD_NAME : PS4RF_BOOTDIAG_METHOD_MIB;
    } else {
        /* no complete timeval: partial (short result) is reported as such, never accepted */
        if (info->name_class == PS4RF_BOOT_SYSCTL_SHORT_RESULT ||
            info->mib_class == PS4RF_BOOT_SYSCTL_SHORT_RESULT) {
            info->run_status = PS4RF_BOOT_RUN_PARTIAL;
        } else {
            info->run_status = PS4RF_BOOT_RUN_READ_FAILED;
        }
        return info->run_status;
    }

    info->sec1 = le64(info->diag.name_path.raw);
    info->usec1 = le64(info->diag.name_path.raw + 8);
    if (info->preferred_path == PS4RF_BOOTDIAG_METHOD_MIB) {
        info->sec1 = le64(info->diag.mib_path.raw);
        info->usec1 = le64(info->diag.mib_path.raw + 8);
    }

    /* step 2: stability -- only with a complete timeval, second reading after the bounded pause */
    if (p->sleep_us != NULL) p->sleep_us(PS4RF_BOOT_PAUSE_US);
    {
        ps4rf_bootdiag_result second;
        memset(&second, 0, sizeof(second));
        if (p->boot_diag(&second) != PS4RF_TF_OK) {
            info->run_status = PS4RF_BOOT_RUN_READ_FAILED;
            return info->run_status;
        }
        if (info->preferred_path == PS4RF_BOOTDIAG_METHOD_MIB) {
            info->sec2 = le64(second.mib_path.raw);
            info->usec2 = le64(second.mib_path.raw + 8);
            if (classify(&second.mib_path) != PS4RF_BOOT_SYSCTL_SUCCESS) {
                info->run_status = PS4RF_BOOT_RUN_READ_FAILED;
                return info->run_status;
            }
        } else {
            info->sec2 = le64(second.name_path.raw);
            info->usec2 = le64(second.name_path.raw + 8);
            if (classify(&second.name_path) != PS4RF_BOOT_SYSCTL_SUCCESS) {
                info->run_status = PS4RF_BOOT_RUN_READ_FAILED;
                return info->run_status;
            }
        }
    }
    info->reads_identical = (info->sec1 == info->sec2 && info->usec1 == info->usec2);
    if (!info->reads_identical) {
        info->run_status = PS4RF_BOOT_RUN_NOT_STABLE;
        return info->run_status;
    }

    info->plausible = (info->sec1 > 0 && info->usec1 >= 0 && info->usec1 < 1000000);
    if (p->wall_sec != NULL && p->wall_sec(&wall) == PS4RF_TF_OK) {
        info->wall_clock_ok = 1;
        info->console_wall_sec = wall;
        if (info->sec1 > wall) {
            info->boottime_after_wall_clock = 1;
            info->plausible = 0;
        }
    }
    info->run_status = info->plausible ? PS4RF_BOOT_RUN_OK : PS4RF_BOOT_RUN_IMPLAUSIBLE;
    return info->run_status;
}

const char *ps4rf_boot_status_name(int run_status)
{
    switch (run_status) {
        case PS4RF_BOOT_RUN_OK: return "OK";
        case PS4RF_BOOT_RUN_READ_FAILED: return "BOOT_READ_FAILED";
        case PS4RF_BOOT_RUN_NOT_STABLE: return "BOOT_SOURCE_NOT_STABLE";
        case PS4RF_BOOT_RUN_IMPLAUSIBLE: return "BOOT_TIME_IMPLAUSIBLE";
        case PS4RF_BOOT_RUN_PARTIAL: return "BOOT_SOURCE_PARTIAL";
        case PS4RF_BOOT_RUN_CONFLICT: return "BOOT_SOURCE_CONFLICT";
        default: return "BOOT_STATUS_UNKNOWN";
    }
}

const char *ps4rf_boot_class_name(int classification)
{
    switch (classification) {
        case PS4RF_BOOT_SYSCTL_SUCCESS: return "BOOT_SYSCTL_SUCCESS";
        case PS4RF_BOOT_SYSCTL_NAME_NOT_FOUND: return "BOOT_SYSCTL_NAME_NOT_FOUND";
        case PS4RF_BOOT_SYSCTL_MIB_NOT_FOUND: return "BOOT_SYSCTL_MIB_NOT_FOUND";
        case PS4RF_BOOT_SYSCTL_PERMISSION: return "BOOT_SYSCTL_PERMISSION";
        case PS4RF_BOOT_SYSCTL_INVALID_ARGUMENT: return "BOOT_SYSCTL_INVALID_ARGUMENT";
        case PS4RF_BOOT_SYSCTL_SIZE_QUERY_FAILED: return "BOOT_SYSCTL_SIZE_QUERY_FAILED";
        case PS4RF_BOOT_SYSCTL_READ_FAILED: return "BOOT_SYSCTL_READ_FAILED";
        case PS4RF_BOOT_SYSCTL_SHORT_RESULT: return "BOOT_SYSCTL_SHORT_RESULT";
        case PS4RF_BOOT_SYSCTL_MALFORMED_RESULT: return "BOOT_SYSCTL_MALFORMED_RESULT";
        default: return "BOOT_SYSCTL_CLASS_UNKNOWN";
    }
}

const char *ps4rf_boot_method_name(int method)
{
    if (method == PS4RF_BOOTDIAG_METHOD_NAME) return "sysctlbyname";
    if (method == PS4RF_BOOTDIAG_METHOD_MIB) return "sysctl_mib";
    return "none";
}

/* ------------------------------------------------------------------ event */

static int set_method_object(jval *event, const char *key, const ps4rf_bootdiag_method *m,
                             int classification)
{
    jval *obj = jval_new_object();
    char buf[8][24];
    char raw_hex[2u * PS4RF_BOOTDIAG_MAX_BYTES + 1u];
    unsigned char digest[32];
    char digest_hex[65];
    if (obj == NULL) return -1;
    dec_ll(buf[0], sizeof(buf[0]), (long long)m->method);
    dec_ll(buf[1], sizeof(buf[1]), (long long)m->size_query_rc);
    dec_ll(buf[2], sizeof(buf[2]), (long long)m->size_query_errno);
    dec_ll(buf[3], sizeof(buf[3]), m->reported_size);
    dec_ll(buf[4], sizeof(buf[4]), (long long)m->read_rc);
    dec_ll(buf[5], sizeof(buf[5]), (long long)m->read_errno);
    dec_ll(buf[6], sizeof(buf[6]), m->returned_size);
    dec_ll(buf[7], sizeof(buf[7]), (long long)m->requested_size);
    ps4rf_sha256(m->raw, (size_t)m->raw_len, digest);
    hex_bytes(digest_hex, sizeof(digest_hex), digest, 32u);
    hex_bytes(raw_hex, sizeof(raw_hex), m->raw, m->raw_len);
    if (jval_obj_set(obj, "method", jval_new_string(ps4rf_boot_method_name(m->method))) != 0 ||
        jval_obj_set(obj, "method_id", jval_new_int((int64_t)m->method)) != 0 ||
        jval_obj_set(obj, "size_query_attempted", jval_new_bool(m->size_query_attempted ? 1 : 0)) != 0 ||
        jval_obj_set(obj, "size_query_rc", jval_new_string(buf[1])) != 0 ||
        jval_obj_set(obj, "size_query_errno", jval_new_string(buf[2])) != 0 ||
        jval_obj_set(obj, "reported_size", jval_new_string(buf[3])) != 0 ||
        jval_obj_set(obj, "read_attempted", jval_new_bool(m->read_attempted ? 1 : 0)) != 0 ||
        jval_obj_set(obj, "read_rc", jval_new_string(buf[4])) != 0 ||
        jval_obj_set(obj, "read_errno", jval_new_string(buf[5])) != 0 ||
        jval_obj_set(obj, "requested_size", jval_new_string(buf[7])) != 0 ||
        jval_obj_set(obj, "returned_size", jval_new_string(buf[6])) != 0 ||
        jval_obj_set(obj, "raw_len", jval_new_int((int64_t)m->raw_len)) != 0 ||
        jval_obj_set(obj, "raw_max_bytes", jval_new_int((int64_t)PS4RF_BOOTDIAG_MAX_BYTES)) != 0 ||
        jval_obj_set(obj, "raw_sha256", jval_new_string(digest_hex)) != 0 ||
        jval_obj_set(obj, "raw_hex", jval_new_string(raw_hex)) != 0 ||
        jval_obj_set(obj, "classification_id", jval_new_int((int64_t)classification)) != 0 ||
        jval_obj_set(obj, "classification", jval_new_string(ps4rf_boot_class_name(classification))) != 0) {
        jval_free(obj);
        return -1;
    }
    if (jval_obj_set(event, key, obj) != 0) {
        jval_free(obj);
        return -1;
    }
    return 0;
}

jval *ps4rf_boot_event(const ps4rf_boot_info *info, const char *build_id, const char *label)
{
    jval *event;
    jval *r1;
    jval *r2;
    jval *methods;
    char s1[24], u1[24], s2[24], u2[24], wall[24], tv[24];
    int ok;
    if (info == NULL) return NULL;
    event = jval_new_object();
    r1 = jval_new_object();
    r2 = jval_new_object();
    methods = jval_new_object();
    if (event == NULL || r1 == NULL || r2 == NULL || methods == NULL) {
        jval_free(event); jval_free(r1); jval_free(r2); jval_free(methods);
        return NULL;
    }
    ok = (info->run_status == PS4RF_BOOT_RUN_OK);
    dec_ll(s1, sizeof(s1), info->sec1);
    dec_ll(u1, sizeof(u1), info->usec1);
    dec_ll(s2, sizeof(s2), info->sec2);
    dec_ll(u2, sizeof(u2), info->usec2);
    dec_ll(wall, sizeof(wall), info->console_wall_sec);
    dec_ll(tv, sizeof(tv), info->diag.timeval_sizeof);

    if (set_method_object(methods, "sysctlbyname", &info->diag.name_path, info->name_class) != 0 ||
        set_method_object(methods, "sysctl_mib", &info->diag.mib_path, info->mib_class) != 0) {
        jval_free(event); jval_free(r1); jval_free(r2); jval_free(methods);
        return NULL;
    }
    if (jval_obj_set(r1, "sec", jval_new_string(s1)) != 0 ||
        jval_obj_set(r1, "usec", jval_new_string(u1)) != 0 ||
        jval_obj_set(r2, "sec", jval_new_string(s2)) != 0 ||
        jval_obj_set(r2, "usec", jval_new_string(u2)) != 0) {
        jval_free(event); jval_free(r1); jval_free(r2); jval_free(methods);
        return NULL;
    }

    if (jval_obj_set(event, "msg", jval_new_string("EVENT")) != 0 ||
        jval_obj_set(event, "event", jval_new_string("boot.binding")) != 0 ||
        jval_obj_set(event, "schema", jval_new_string("ps4rf.boot.binding.diag.v1")) != 0 ||
        jval_obj_set(event, "status", jval_new_string(ok ? "OK" : "FAILED")) != 0 ||
        jval_obj_set(event, "source", jval_new_string(PS4RF_BOOT_SOURCE)) != 0 ||
        jval_obj_set(event, "source_kind", jval_new_string(PS4RF_BOOT_SOURCE_KIND)) != 0 ||
        jval_obj_set(event, "no_kernel_access", jval_new_bool(1)) != 0 ||
        jval_obj_set(event, "no_kexec", jval_new_bool(1)) != 0 ||
        jval_obj_set(event, "no_kernel_address", jval_new_bool(1)) != 0 ||
        jval_obj_set(event, "no_rva_sent_to_host", jval_new_bool(1)) != 0 ||
        jval_obj_set(event, "userland_only", jval_new_bool(1)) != 0 ||
        jval_obj_set(event, "run_status", jval_new_int((int64_t)info->run_status)) != 0 ||
        jval_obj_set(event, "run_status_name",
                     jval_new_string(ps4rf_boot_status_name(info->run_status))) != 0 ||
        jval_obj_set(event, "preferred_path",
                     jval_new_string(ps4rf_boot_method_name(info->preferred_path))) != 0 ||
        jval_obj_set(event, "both_paths_identical",
                     jval_new_bool(info->both_identical ? 1 : 0)) != 0 ||
        jval_obj_set(event, "timeval_sizeof", jval_new_string(tv)) != 0 ||
        jval_obj_set(event, "timeval_contract_bytes",
                     jval_new_int((int64_t)PS4RF_BOOT_TIMEVAL_BYTES)) != 0 ||
        jval_obj_set(event, "pause_us", jval_new_int((int64_t)info->pause_us)) != 0 ||
        jval_obj_set(event, "methods", methods) != 0 ||
        jval_obj_set(event, "read1", r1) != 0 ||
        jval_obj_set(event, "read2", r2) != 0 ||
        jval_obj_set(event, "reads_identical", jval_new_bool(info->reads_identical ? 1 : 0)) != 0 ||
        jval_obj_set(event, "stability",
                     jval_new_string(info->reads_identical ? "STABLE" : "BOOT_SOURCE_NOT_STABLE")) != 0 ||
        jval_obj_set(event, "complete_timeval",
                     jval_new_bool((info->preferred_path >= 0 && info->reads_identical) ? 1 : 0)) != 0 ||
        jval_obj_set(event, "wall_clock_ok", jval_new_bool(info->wall_clock_ok ? 1 : 0)) != 0 ||
        jval_obj_set(event, "console_wall_sec",
                     info->wall_clock_ok ? jval_new_string(wall) : jval_new_null()) != 0 ||
        jval_obj_set(event, "boottime_after_wall_clock",
                     jval_new_bool(info->boottime_after_wall_clock ? 1 : 0)) != 0 ||
        jval_obj_set(event, "plausible", jval_new_bool(info->plausible ? 1 : 0)) != 0 ||
        jval_obj_set(event, "errno_observable",
                     jval_new_bool(info->diag.errno_observable ? 1 : 0)) != 0 ||
        jval_obj_set(event, "canonical_derivation",
                     jval_new_string("host side: tools/profiles/bootid.py, ps4rf.boot-binding.v1")) != 0 ||
        jval_obj_set(event, "build_id", jval_new_string(build_id == NULL ? "" : build_id)) != 0 ||
        jval_obj_set(event, "label", jval_new_string(label == NULL ? "" : label)) != 0) {
        jval_free(event); jval_free(r1); jval_free(r2); jval_free(methods);
        return NULL;
    }
    return event;
}
