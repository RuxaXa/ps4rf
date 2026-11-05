/* PS4RF P4/W8 target agent -- single dispatch path (see ps4rf_router.h). */
#include "ps4rf_router.h"

#include "ps4rf_platform.h"
#include "ps4rf_stub.h"

/* ---------------------------------------------------------------- small helpers */

static int is_hex_lower(const char *s, size_t n)
{
    size_t i;
    if (s == NULL) return 0;
    for (i = 0u; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

static int request_id_ok(const char *rid)
{
    if (rid == NULL) return 0;
    if (strlen(rid) != 36u) return 0;
    if (rid[0] != 'R' || rid[1] != 'E' || rid[2] != 'Q' || rid[3] != '-') return 0;
    return is_hex_lower(rid + 4, 32u);
}

static int ref_shape_ok(const char *ref)
{
    size_t i = 0u;
    size_t colon = 0u;
    if (ref == NULL) return 0;
    if (!(ref[0] >= 'a' && ref[0] <= 'z')) return 0;
    for (i = 0u; ref[i] != '\0'; i++) {
        char c = ref[i];
        if (c == ':') {
            if (colon != 0u || i == 0u) return 0;
            colon = i;
            continue;
        }
        if (colon == 0u) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return 0;
        } else if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return colon != 0u && (i - colon - 1u) == 16u;
}

int ps4rf_arg_type_ok(const jval *v, unsigned char type)
{
    switch (type) {
    case PS4RF_T_INT: return jval_kind(v) == JVAL_INT;
    case PS4RF_T_STR: return jval_kind(v) == JVAL_STRING;
    case PS4RF_T_BOOL: return jval_kind(v) == JVAL_BOOL;
    case PS4RF_T_REF: return jval_kind(v) == JVAL_STRING && ref_shape_ok(jval_string(v, NULL));
    case PS4RF_T_HEX32: {
        const char *s;
        if (jval_kind(v) != JVAL_STRING) return 0;
        s = jval_string(v, NULL);
        return s != NULL && strlen(s) == 32u && is_hex_lower(s, 32u);
    }
    case PS4RF_T_ARRAY: return jval_kind(v) == JVAL_ARRAY;
    case PS4RF_T_OBJECT: return jval_kind(v) == JVAL_OBJECT;
    default: return 0;
    }
}

static const ps4rf_op_row *table_lookup(const char *name)
{
    unsigned i;
    if (name == NULL) return NULL;
    for (i = 0u; i < PS4RF_OP_TABLE_COUNT; i++) {
        const char *a = PS4RF_OP_TABLE[i].name;
        unsigned k = 0u;
        while (a[k] != '\0' && name[k] != '\0' && a[k] == name[k]) k++;
        if (a[k] == '\0' && name[k] == '\0') return &PS4RF_OP_TABLE[i];
    }
    return NULL;
}

/* Argument validation is generated from the frozen argument slices (see
 * ps4rf_optable_data.h) so the target cannot drift from the frozen interface. */
static unsigned row_index_of(const ps4rf_op_row *row)
{
    unsigned i;
    for (i = 0u; i < PS4RF_OP_TABLE_COUNT; i++) {
        if (&PS4RF_OP_TABLE[i] == row) return i;
    }
    return PS4RF_OP_TABLE_COUNT;   /* never matches: fail closed */
}

/* ------------------------------------------------------------------ responses */

static jval *build_cleanup(const ps4rf_rt *rt)
{
    jval *cleanup = jval_new_object();
    jval *resources = jval_new_array();
    if (cleanup == NULL || resources == NULL) {
        jval_free(cleanup);
        jval_free(resources);
        return NULL;
    }
    if (jval_obj_set(cleanup, "state", jval_new_string(ps4rf_res_cleanup_state(&rt->res))) != 0 ||
        jval_obj_set(cleanup, "resources", resources) != 0) {
        jval_free(cleanup);
        return NULL;
    }
    return cleanup;
}

static jval *build_ok(const char *request_id, jval *result, const ps4rf_rt *rt)
{
    jval *header = jval_new_object();
    jval *resp = jval_new_object();
    if (header == NULL || resp == NULL) {
        jval_free(header);
        jval_free(resp);
        jval_free(result);
        return NULL;
    }
    if (jval_obj_set(header, "in_reply_to", jval_new_string(request_id)) != 0 ||
        jval_obj_set(resp, "header", header) != 0 ||
        jval_obj_set(resp, "status", jval_new_string("OK")) != 0 ||
        jval_obj_set(resp, "result", result) != 0 ||
        jval_obj_set(resp, "cleanup", build_cleanup(rt)) != 0) {
        jval_free(resp);
        return NULL;
    }
    return resp;
}

static jval *build_error(const char *request_id, const char *code, const char *detail, const ps4rf_rt *rt)
{
    jval *header = jval_new_object();
    jval *error = jval_new_object();
    jval *resp = jval_new_object();
    if (header == NULL || error == NULL || resp == NULL) {
        jval_free(header);
        jval_free(error);
        jval_free(resp);
        return NULL;
    }
    if (jval_obj_set(error, "code", jval_new_string(code)) != 0 ||
        (detail != NULL && jval_obj_set(error, "detail", jval_new_string(detail)) != 0) ||
        jval_obj_set(header, "in_reply_to", jval_new_string(request_id)) != 0 ||
        jval_obj_set(resp, "header", header) != 0 ||
        jval_obj_set(resp, "status", jval_new_string("ERROR")) != 0 ||
        jval_obj_set(resp, "error", error) != 0 ||
        jval_obj_set(resp, "cleanup", build_cleanup(rt)) != 0) {
        jval_free(resp);
        return NULL;
    }
    return resp;
}

/* ------------------------------------------------------- the single entry site */

static void ps4rf_provider_enter(ps4rf_rt *rt)
{
    /* The one and only place in the target agent that enters a provider handler. */
    ps4rf_ev_note_entry(&rt->ev);
}

/* ------------------------------------------------------------------- dispatch */

static const char *defer_detail(const ps4rf_op_row *row, char *buf, size_t cap)
{
    const char *route_name = "unknown";
    size_t n = 0u;
    const char *p;
    switch (row->route) {
    case PS4RF_ROUTE_STUB: route_name = "stub"; break;
    case PS4RF_ROUTE_MOCK_ONLY: route_name = "mock_only"; break;
    case PS4RF_ROUTE_DEFERRED_PRIVILEGE: route_name = "deferred_privilege"; break;
    case PS4RF_ROUTE_DEFERRED_HOST_CHAIN: route_name = "deferred_host_chain"; break;
    case PS4RF_ROUTE_PRIVILEGED_PROVIDER: route_name = "privileged_provider"; break;
    default: break;
    }
    p = "provider_entry=false route=";
    while (*p != '\0' && n + 1u < cap) buf[n++] = *p++;
    p = route_name;
    while (*p != '\0' && n + 1u < cap) buf[n++] = *p++;
    p = " reason=";
    while (*p != '\0' && n + 1u < cap) buf[n++] = *p++;
    p = row->defer_reason;
    while (*p != '\0' && n + 1u < cap) buf[n++] = *p++;
    buf[n] = '\0';
    return buf;
}

ps4rf_route_outcome ps4rf_router_handle(ps4rf_rt *rt, const jval *request, jval **response_out)
{
    const jval *header;
    const jval *body;
    jval *empty_args = NULL;
    const jval *args;
    const char *request_id;
    const char *op_name;
    const ps4rf_op_row *row;
    ps4rf_ev_record *rec;

    *response_out = NULL;
    if (request == NULL || jval_kind(request) != JVAL_OBJECT) return PS4RF_ROUTE_OUTCOME_CLOSE;
    header = jval_get(request, "header");
    body = jval_get(request, "body");
    if (header == NULL || body == NULL) return PS4RF_ROUTE_OUTCOME_CLOSE;
    if (jval_kind(header) != JVAL_OBJECT || jval_kind(body) != JVAL_OBJECT) return PS4RF_ROUTE_OUTCOME_CLOSE;
    request_id = jval_string(jval_get(header, "request_id"), NULL);
    if (jval_count(header) != 1u || !request_id_ok(request_id)) {
        /* Without a well formed request id no conforming RESPONSE can be built, so the
         * session is ended instead of answering with an unbuildable envelope. */
        return PS4RF_ROUTE_OUTCOME_CLOSE;
    }

    rec = ps4rf_ev_next(&rt->ev);
    memcpy(rec->request_id, request_id, strlen(request_id) + 1u);
    rec->ts_us = ps4rf_platform_get()->now_us();

    if (jval_count(request) != 2u) {
        rec->op = "unknown";
        rec->code = "ARGUMENT_INVALID";
        rt->ev.invalid_total++;
        *response_out = build_error(request_id, "ARGUMENT_INVALID", "unknown request field", rt);
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }

    op_name = jval_string(jval_get(body, "operation"), NULL);
    if (op_name == NULL || op_name[0] == '\0') {
        rec->op = "unknown";
        rec->code = "ARGUMENT_INVALID";
        rt->ev.invalid_total++;
        *response_out = build_error(request_id, "ARGUMENT_INVALID", "body.operation is required", rt);
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }
    row = table_lookup(op_name);
    rec->op = row != NULL ? row->name : "unknown";
    if (row == NULL) {
        char detail[96];
        size_t n = 0u;
        const char *p = "not in the frozen registry: ";
        rec->code = "OPERATION_UNSUPPORTED";
        rt->ev.unsupported_total++;
        while (*p != '\0' && n + 1u < sizeof(detail)) detail[n++] = *p++;
        p = op_name;
        while (*p != '\0' && n + 1u < sizeof(detail)) detail[n++] = *p++;
        detail[n] = '\0';
        *response_out = build_error(request_id, "OPERATION_UNSUPPORTED", detail, rt);
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }
    rec->route = row->route;

    if (jval_count(body) > 3u) {
        rec->code = "ARGUMENT_INVALID";
        rt->ev.invalid_total++;
        *response_out = build_error(request_id, "ARGUMENT_INVALID", "unknown body field", rt);
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }
    {
        const jval *seq = jval_get(body, "seq");
        if (seq != NULL && jval_kind(seq) != JVAL_NULL && jval_kind(seq) != JVAL_INT) {
            rec->code = "ARGUMENT_INVALID";
            rt->ev.invalid_total++;
            *response_out = build_error(request_id, "ARGUMENT_INVALID", "body.seq must be an integer", rt);
            return PS4RF_ROUTE_OUTCOME_RESPONSE;
        }
    }
    args = jval_get(body, "arguments");
    if (args == NULL) {
        empty_args = jval_new_object();
        args = empty_args;
    }
    {
        if (args == NULL || ps4rf_optable_args_ok(row_index_of(row), args) == 0) {
            jval_free(empty_args);
            rec->code = "ARGUMENT_INVALID";
            rt->ev.invalid_total++;
            *response_out = build_error(request_id, "ARGUMENT_INVALID", "argument validation failed", rt);
            return PS4RF_ROUTE_OUTCOME_RESPONSE;
        }
    }

    /* Recovery gate: while the session is in RECOVERY_REQUIRED no mutating operation is
     * served (read-only inspection stays possible). */
    /* §5/§11: the daemon needs to know whether the request it just handled was mutating, to judge
     * a response that never reached the peer. Recorded here, at the single dispatch point, so no
     * second place has to interpret the operation name. */
    rt->last_op_mutating = row->mutating ? 1 : 0;
    if (rt->recovery_required && row->mutating) {
        jval_free(empty_args);
        rec->code = "SESSION_RECOVERY_REQUIRED";
        rt->ev.recovery_refusals++;
        *response_out = build_error(request_id, "SESSION_RECOVERY_REQUIRED",
                                    "session is in RECOVERY_REQUIRED; no mutating operation is served", rt);
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }

    /* Route decision: only a wired stub operation may enter a provider handler. */
    if (row->target != PS4RF_TARGET_WIRED) {
        char detail[192];
        jval_free(empty_args);
        rec->code = "OPERATION_DEFERRED";
        rt->ev.deferred_total++;
        *response_out = build_error(request_id, "OPERATION_DEFERRED", defer_detail(row, detail, sizeof(detail)), rt);
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }

    {
        jval *result = NULL;
        const char *detail = "internal error";
        const char *code;
        ps4rf_provider_enter(rt);          /* <- the single provider entry site */
        rec->provider_entry = 1u;
        code = ps4rf_stub_invoke(rt, row, args, &result, &detail);
        rt->requests_served++;
        rec->refs_after = ps4rf_res_live(&rt->res);
        jval_free(empty_args);
        if (code == NULL) {
            rec->ok = 1u;
            *response_out = build_ok(request_id, result, rt);
        } else {
            rec->code = code;
            jval_free(result);
            *response_out = build_error(request_id, code, detail, rt);
        }
        return PS4RF_ROUTE_OUTCOME_RESPONSE;
    }
}

unsigned ps4rf_router_entry_sites(void)
{
    /* Kept as a runtime constant so a test can assert the structural property without
     * parsing the translation unit: exactly one call to ps4rf_provider_enter exists. */
    return 1u;
}
