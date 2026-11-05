/* PS4RF P4/W8 target agent -- target attestation (see ps4rf_telemetry.h). */
#include "ps4rf_telemetry.h"

#include "sha256.h"

#include "ps4rf_optable_data.h"

static void copy_field(char *dst, size_t cap, const char *src)
{
    size_t n = 0u;
    if (cap == 0u) return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    while (src[n] != '\0' && n + 1u < cap) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

static void hex16_upper(const uint8_t *raw, char *out)
{
    static const char digits[] = "0123456789ABCDEF";
    unsigned i;
    for (i = 0u; i < 8u; i++) {
        out[i * 2u] = digits[(raw[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = digits[raw[i] & 0x0fu];
    }
    out[16] = '\0';
}

static void put_int(char *dst, size_t cap, long long value)
{
    char tmp[24];
    unsigned n = 0u;
    unsigned i;
    int negative = value < 0;
    unsigned long long v = negative ? (unsigned long long)(-value) : (unsigned long long)value;
    if (v == 0ull) tmp[n++] = '0';
    while (v > 0ull && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (int)(v % 10ull));
        v /= 10ull;
    }
    dst[0] = '\0';
    i = 0u;
    if (negative && i + 1u < cap) dst[i++] = '-';
    while (n > 0u && i + 1u < cap) dst[i++] = tmp[--n];
    dst[i] = '\0';
}

void ps4rf_telemetry_collect(ps4rf_telemetry *tel)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    char buf[PS4RF_TEL_FIELD_MAX];
    size_t len = 0u;
    uint8_t digest[32];
    char seed[256];
    unsigned n = 0u;

    if (tel == NULL || pf == NULL) return;
    memset(tel, 0, sizeof(*tel));

    copy_field(tel->platform, sizeof(tel->platform), pf->identity);
    copy_field(tel->architecture, sizeof(tel->architecture), "x86_64");
    copy_field(tel->nonce_source, sizeof(tel->nonce_source),
               pf->nonce_source_os_entropy ? "operating-system entropy" : "measured mix (no OS entropy source)");

    tel->firmware_status = PS4RF_TF_UNRESOLVED;
    if (pf->firmware != NULL && pf->firmware(buf, sizeof(buf), &len) == PS4RF_TF_OK && len > 0u) {
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1u] = '\0';
        copy_field(tel->firmware, sizeof(tel->firmware), buf);
        tel->firmware_status = PS4RF_TF_OK;
    }

    tel->model_status = PS4RF_TF_UNRESOLVED;
    len = 0u;
    if (pf->model != NULL && pf->model(buf, sizeof(buf), &len) == PS4RF_TF_OK && len > 0u) {
        buf[len < sizeof(buf) ? len : sizeof(buf) - 1u] = '\0';
        copy_field(tel->model, sizeof(tel->model), buf);
        tel->model_status = PS4RF_TF_OK;
    }

    tel->process_id_status = PS4RF_TF_UNRESOLVED;
    if (pf->process_id != NULL && pf->process_id(&tel->process_id) == PS4RF_TF_OK) {
        tel->process_id_status = PS4RF_TF_OK;
    }

    tel->boot_time_status = PS4RF_TF_UNRESOLVED;
    if (pf->boot_time_epoch != NULL && pf->boot_time_epoch(&tel->boot_time_epoch) == PS4RF_TF_OK) {
        tel->boot_time_status = PS4RF_TF_OK;
    }

    /* boot_id only from measured boot facts; otherwise no identifier at all. */
    tel->boot_id_ok = 0;
    tel->boot_id[0] = '\0';
    copy_field(tel->boot_id_source, sizeof(tel->boot_id_source), "unresolved");
    if (tel->firmware_status == PS4RF_TF_OK && tel->boot_time_status == PS4RF_TF_OK) {
        char boot_sec[24];
        const char *p;
        put_int(boot_sec, sizeof(boot_sec), tel->boot_time_epoch);
        p = "ps4rf/boot/v1|";
        while (*p != '\0' && n < sizeof(seed) - 1u) seed[n++] = *p++;
        p = tel->firmware;
        while (*p != '\0' && n < sizeof(seed) - 1u) seed[n++] = *p++;
        seed[n++] = '|';
        p = tel->model_status == PS4RF_TF_OK ? tel->model : "unresolved-model";
        while (*p != '\0' && n < sizeof(seed) - 1u) seed[n++] = *p++;
        seed[n++] = '|';
        p = boot_sec;
        while (*p != '\0' && n < sizeof(seed) - 1u) seed[n++] = *p++;
        ps4rf_sha256(seed, (size_t)n, digest);
        tel->boot_id[0] = 'B'; tel->boot_id[1] = 'O'; tel->boot_id[2] = 'O'; tel->boot_id[3] = 'T';
        tel->boot_id[4] = '-';
        hex16_upper(digest, tel->boot_id + 5);
        tel->boot_id_ok = 1;
        copy_field(tel->boot_id_source, sizeof(tel->boot_id_source), "derived from firmware identity + model + kern.boottime");
    } else {
        copy_field(tel->boot_id_source, sizeof(tel->boot_id_source),
                   "BOOT_ID_UNVERIFIED: firmware identity or boot time not readable through a read-only userland API");
    }
}

static jval *fact_status(ps4rf_fact_status st)
{
    return jval_new_string(st == PS4RF_TF_OK ? "OK" : "UNRESOLVED");
}

static const char *value_or_unresolved(const char *value, ps4rf_fact_status st)
{
    return st == PS4RF_TF_OK ? value : "UNRESOLVED";
}

jval *ps4rf_telemetry_ready_body(const ps4rf_telemetry *tel, const char *build_id,
                                 unsigned protocol_version, unsigned max_frame_bytes,
                                 unsigned lifetime_s, unsigned idle_s, const char *provider_id)
{
    jval *root = jval_new_object();
    jval *agent = jval_new_object();
    jval *caps = jval_new_object();
    jval *wired = jval_new_array();
    jval *boot = jval_new_object();
    jval *limits = jval_new_object();
    jval *profile = jval_new_object();
    jval *provider = jval_new_object();
    jval *target = jval_new_object();
    unsigned i;
    unsigned wired_count = 0u;
    unsigned deferred_count = 0u;

    if (root == NULL || agent == NULL || caps == NULL || wired == NULL || boot == NULL ||
        limits == NULL || profile == NULL || provider == NULL || target == NULL) {
        jval_free(root); jval_free(agent); jval_free(caps); jval_free(wired);
        jval_free(boot); jval_free(limits); jval_free(profile); jval_free(provider); jval_free(target);
        return NULL;
    }
    for (i = 0u; i < PS4RF_OP_TABLE_COUNT; i++) {
        if (PS4RF_OP_TABLE[i].target == PS4RF_TARGET_WIRED) {
            wired_count++;
            if (jval_arr_add(wired, jval_new_string(PS4RF_OP_TABLE[i].name)) != 0) { jval_free(root); return NULL; }
        } else {
            deferred_count++;
        }
    }
    if (jval_obj_set(agent, "build", jval_new_string(build_id)) != 0 ||
        jval_obj_set(agent, "name", jval_new_string("ps4rfd-target")) != 0 ||
        jval_obj_set(agent, "version", jval_new_string("w8-1")) != 0 ||
        jval_obj_set(caps, "deferred_count", jval_new_int((int64_t)deferred_count)) != 0 ||
        jval_obj_set(caps, "table_sha256", jval_new_string(PS4RF_OP_TABLE_SHA256)) != 0 ||
        jval_obj_set(caps, "total_ops", jval_new_int((int64_t)PS4RF_OP_TABLE_COUNT)) != 0 ||
        jval_obj_set(caps, "wired", wired) != 0 ||
        jval_obj_set(caps, "wired_count", jval_new_int((int64_t)wired_count)) != 0 ||
        jval_obj_set(boot, "boot_id", tel->boot_id_ok ? jval_new_string(tel->boot_id) : jval_new_null()) != 0 ||
        jval_obj_set(boot, "boot_time_epoch", tel->boot_time_status == PS4RF_TF_OK
                                                    ? jval_new_int((int64_t)tel->boot_time_epoch)
                                                    : jval_new_null()) != 0 ||
        jval_obj_set(boot, "source", jval_new_string(tel->boot_id_source)) != 0 ||
        jval_obj_set(boot, "status", jval_new_string(tel->boot_id_ok ? "DERIVED" : "BOOT_ID_UNVERIFIED")) != 0 ||
        jval_obj_set(limits, "idle_seconds", jval_new_int((int64_t)idle_s)) != 0 ||
        jval_obj_set(limits, "lifetime_seconds", jval_new_int((int64_t)lifetime_s)) != 0 ||
        jval_obj_set(limits, "max_frame_bytes", jval_new_int((int64_t)max_frame_bytes)) != 0 ||
        jval_obj_set(limits, "protocol_version", jval_new_int((int64_t)protocol_version)) != 0 ||
        jval_obj_set(profile, "sha256", jval_new_null()) != 0 ||
        jval_obj_set(profile, "status", jval_new_string("UNBOUND")) != 0 ||
        jval_obj_set(profile, "note", jval_new_string("on-site profile review pending; no fixture is promoted to a live profile")) != 0 ||
        jval_obj_set(provider, "deferred_ops", jval_new_int((int64_t)deferred_count)) != 0 ||
        jval_obj_set(provider, "id", jval_new_string(provider_id)) != 0 ||
        jval_obj_set(provider, "state", jval_new_string("WIRED")) != 0 ||
        jval_obj_set(provider, "wired_ops", jval_new_int((int64_t)wired_count)) != 0 ||
        jval_obj_set(root, "agent", agent) != 0 ||
        jval_obj_set(root, "capabilities", caps) != 0 ||
        jval_obj_set(root, "boot", boot) != 0 ||
        jval_obj_set(root, "limits", limits) != 0 ||
        jval_obj_set(root, "msg", jval_new_string("READY")) != 0 ||
        jval_obj_set(root, "nonce_source", jval_new_string(tel->nonce_source)) != 0 ||
        jval_obj_set(root, "profile", profile) != 0 ||
        jval_obj_set(root, "provider", provider) != 0 ||
        jval_obj_set(root, "protocol_version", jval_new_int((int64_t)protocol_version)) != 0 ||
        jval_obj_set(root, "target", target) != 0) {
        jval_free(root);
        return NULL;
    }
    if (jval_obj_set(target, "architecture", jval_new_string(tel->architecture)) != 0 ||
        jval_obj_set(target, "firmware", jval_new_string(value_or_unresolved(tel->firmware, tel->firmware_status))) != 0 ||
        jval_obj_set(target, "firmware_status", fact_status(tel->firmware_status)) != 0 ||
        jval_obj_set(target, "model", jval_new_string(value_or_unresolved(tel->model, tel->model_status))) != 0 ||
        jval_obj_set(target, "model_status", fact_status(tel->model_status)) != 0 ||
        jval_obj_set(target, "pid", tel->process_id_status == PS4RF_TF_OK
                                          ? jval_new_int((int64_t)tel->process_id)
                                          : jval_new_null()) != 0 ||
        jval_obj_set(target, "pid_status", fact_status(tel->process_id_status)) != 0 ||
        jval_obj_set(target, "platform", jval_new_string(tel->platform)) != 0) {
        jval_free(root);
        return NULL;
    }
    return root;
}
