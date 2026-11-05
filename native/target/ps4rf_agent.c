/* PS4RF P4/W8 target agent -- session driver (see ps4rf_agent.h). */
#include "ps4rf_agent.h"

#include "ps4rf_platform.h"
#include "ps4rf_router.h"
#include "ps4rf_stub.h"

#if defined(PS4RF_TARGET_ATTEST) || defined(PS4RF_TARGET_BOOTID) || \
    defined(PS4RF_TARGET_BOOTREAD)
static int ps4rf_op_is(const char *op, const char *want)
{
    size_t i = 0u;
    if (op == NULL || want == NULL) return 0;
    while (op[i] != '\0' && want[i] != '\0') {
        if (op[i] != want[i]) return 0;
        i++;
    }
    return op[i] == want[i];
}
#endif

#ifdef PS4RF_TARGET_ATTEST
#include "ps4rf_attest.h"

/* W9: the fixed read-only attestation. One invocation per session, triggered by the agent
 * itself right after the first session.status response -- the host never sends an address,
 * a flag or a trigger for it, and a second invocation is refused by the one-shot guard. */
static ps4rf_attest_info g_attest_info;
#endif

#ifdef PS4RF_TARGET_BOOTREAD
#include "ps4rf_bootread.h"

/* W11.2: the fixed privileged boot identity read. Exactly one invocation per session, triggered
 * by the agent itself right after the first session.status response. The host supplies no
 * address, no offset and no length: the source RVA and the 16 byte length are compile-time
 * constants inside the kernel section, and a second invocation is refused by the one-shot guard
 * (which is set before kexec). */
static ps4rf_bootread_info g_bootread_info;
#endif

#ifdef PS4RF_TARGET_BOOTID
#include "ps4rf_boot.h"

/* W11: the read-only userland boot binding. One collection per session, triggered by the agent
 * itself right after the first session.status response. No kexec, no kernel address, no host
 * supplied trigger; a second collection is refused by the one-shot guard. */
static ps4rf_boot_info g_boot_info;
#endif

/* W14 (resident ps4rfd): the session loop keeps NO kernel.read state and NO kernel.read call
 * site. The bounded read lives in the wired privileged provider (ps4rf_stub.c) and is reached
 * only through the dispatcher: authenticated RPC -> router argument validation -> single provider
 * entry -> bounded kernel.read. The structural proof is the build gate, which refuses any
 * occurrence of "kernel.read" in this file.
 *
 * The resident daemon drives this loop through exactly one narrow seam: the checkpoint below
 * (called once per iteration, receives a context, may end the session). It carries no request,
 * no operation and no address, so it cannot drive an operation. */
static ps4rf_agent_checkpoint_fn g_checkpoint = NULL;
static void *g_checkpoint_ctx = NULL;

void ps4rf_agent_set_checkpoint(ps4rf_agent_checkpoint_fn fn, void *ctx)
{
    g_checkpoint = fn;
    g_checkpoint_ctx = ctx;
}

/* --------------------------------------------------------------------- runtime */

void ps4rf_rt_init(ps4rf_rt *rt, const char *session_id, const char *build_id,
                   const char *context, const char *provider_id)
{
    memset(rt, 0, sizeof(*rt));
    ps4rf_ev_init(&rt->ev);
    ps4rf_res_init(&rt->res, session_id);
    ps4rf_telemetry_collect(&rt->tel);
    if (session_id != NULL) {
        size_t n = strlen(session_id);
        if (n >= sizeof(rt->session_id)) n = sizeof(rt->session_id) - 1u;
        memcpy(rt->session_id, session_id, n);
        rt->session_id[n] = '\0';
    }
    if (build_id != NULL) {
        size_t n = strlen(build_id);
        if (n >= sizeof(rt->build_id)) n = sizeof(rt->build_id) - 1u;
        memcpy(rt->build_id, build_id, n);
        rt->build_id[n] = '\0';
    }
    if (context != NULL) {
        size_t n = strlen(context);
        if (n >= sizeof(rt->context)) n = sizeof(rt->context) - 1u;
        memcpy(rt->context, context, n);
        rt->context[n] = '\0';
    }
    rt->provider_id = provider_id;
    rt->state = PS4RF_STATE_HANDSHAKE;
    rt->protocol_version = 1u;
    rt->max_frame_bytes = PS4RF_MAX_FRAME_BYTES_DEFAULT;
    rt->lifetime_s = 900u;
    rt->idle_s = 180u;
}

/* ------------------------------------------------------------------------- I/O */

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    size_t off = 0u;
    while (off < len) {
        int rc = pf->net_send(fd, buf + off, len - off);
        if (rc > 0) {
            off += (size_t)rc;
            continue;
        }
        if (rc == -1) {
            pf->sleep_us(1000u);
            continue;
        }
        return -1;
    }
    return 0;
}

/* 0 on success, 1 on a clean peer close, -1 on a fatal transport failure. */
static int read_full(int fd, uint8_t *buf, size_t len)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    size_t off = 0u;
    while (off < len) {
        int rc = pf->net_recv(fd, buf + off, len - off);
        if (rc > 0) {
            off += (size_t)rc;
            continue;
        }
        if (rc == 0) return 1;
        if (rc == -1) {
            pf->sleep_us(1000u);
            continue;
        }
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------- handshake glue */

static int g_resident_mode = 0;

void ps4rf_agent_set_resident(int on)
{
    g_resident_mode = on ? 1 : 0;
}

int ps4rf_agent_is_resident(void)
{
    return g_resident_mode;
}

const char *ps4rf_agent_platform(void)
{
#if defined(PS4RF_TARGET_PS4)
    return "ps4";
#else
    return "host-standin";
#endif
}

void ps4rf_agent_identity_init(ps4rf_agent_identity *id, const char *build_id, const char *boot_id,
                               long long boot_sec, long long boot_usec, const char *boot_status,
                               int recovery_required)
{
    if (id == NULL) return;
    memset(id, 0, sizeof(*id));
    id->build_id = (build_id != NULL && build_id[0] != '\0') ? build_id : "unresolved";
    id->platform = ps4rf_agent_platform();
    id->profile_id = NULL;
    id->boot_id = boot_id;
    id->boot_sec = boot_sec;
    id->boot_usec = boot_usec;
    id->boot_status = (boot_status != NULL) ? boot_status : "UNRESOLVED";
    id->recovery_required = recovery_required ? 1 : 0;
}

/* W14 §14: the HELLO announces the static agent/boot identity and the boot-wide session state;
 * the nonce is generated fresh for every session, which is what makes every session's
 * transcript and key material unique. Everything here is a fact of this build/boot, never a
 * value carried over from an earlier session. */
static jval *build_hello(const char *label, const char *context, const char *provider,
                         const ps4rf_agent_identity *id)
{
    uint8_t nonce[16];
    char nonce_hex[33];
    jval *hello;
    if (id == NULL) return NULL;
    if (ps4rf_platform_get()->random_bytes(nonce, sizeof(nonce)) != 0) return NULL;
    ps4rf_hex_encode(nonce, sizeof(nonce), nonce_hex);
    hello = jval_new_object();
    if (hello == NULL) return NULL;
    /* Field set and types mirror the pinned HELLO vector (native/src/ps4rfd_main.c) plus the
     * W14 §14 identity block: build_id, platform, profile_id, boot_id, boot_sec, boot_usec and
     * the boot-wide session_state. An identity that does not exist is reported as null. */
    if (jval_obj_set(hello, "agent_version", jval_new_string(PS4RF_AGENT_VERSION)) != 0 ||
        jval_obj_set(hello, "build_id", jval_new_string(id->build_id)) != 0 ||
        jval_obj_set(hello, "context", jval_new_string(context)) != 0 ||
        jval_obj_set(hello, "label", jval_new_string(label)) != 0 ||
        jval_obj_set(hello, "msg", jval_new_string("HELLO")) != 0 ||
        jval_obj_set(hello, "nonce", jval_new_string(nonce_hex)) != 0 ||
        jval_obj_set(hello, "platform", jval_new_string(id->platform)) != 0 ||
        jval_obj_set(hello, "profile_id", id->profile_id != NULL
                                          ? jval_new_string(id->profile_id) : jval_new_null()) != 0 ||
        jval_obj_set(hello, "provider", jval_new_string(provider)) != 0 ||
        jval_obj_set(hello, "recovery_required",
                     jval_new_bool(id->recovery_required ? 1 : 0)) != 0 ||
        jval_obj_set(hello, "session_state", jval_new_string(id->recovery_required
                                                             ? "RECOVERY_REQUIRED" : "READY")) != 0 ||
        jval_obj_set(hello, "boot_id", id->boot_id != NULL
                                       ? jval_new_string(id->boot_id) : jval_new_null()) != 0 ||
        jval_obj_set(hello, "boot_sec", id->boot_sec >= 0
                                        ? jval_new_int(id->boot_sec) : jval_new_null()) != 0 ||
        jval_obj_set(hello, "boot_usec", id->boot_usec >= 0
                                         ? jval_new_int(id->boot_usec) : jval_new_null()) != 0 ||
        jval_obj_set(hello, "boot_status", jval_new_string(id->boot_status)) != 0 ||
        jval_obj_set(hello, "transport", jval_new_string("reverse-tcp")) != 0) {
        jval_free(hello);
        return NULL;
    }
    return hello;
}


static int nonce_from(const jval *obj, uint8_t out[16])
{
    const char *hex = NULL;
    size_t len = 0u;
    const jval *v = jval_get(obj, "nonce");
    if (v == NULL || jval_kind(v) != JVAL_STRING) return -1;
    hex = jval_string(v, &len);
    if (hex == NULL || len != 32u) return -1;
    if (ps4rf_hex_decode(hex, out, 16u, NULL) != PS4RF_OK) return -1;
    return 0;
}

typedef struct {
    ps4rf_keys keys;
    uint8_t pfx_a2h[4];
    uint8_t pfx_h2a[4];
    char session_id[64];
} ps4rf_session_keys;

static ps4rf_status derive_session(const uint8_t psk[32], const jval *hello, const jval *ack,
                                   ps4rf_session_keys *out)
{
    uint8_t agent_nonce[16];
    uint8_t host_nonce[16];
    uint8_t transcript[32];
    char *hello_text = NULL;
    char *ack_text = NULL;
    size_t hello_len = 0u;
    size_t ack_len = 0u;
    const char *err = NULL;
    const char *sid;
    ps4rf_status st;

    if (nonce_from(hello, agent_nonce) != 0 || nonce_from(ack, host_nonce) != 0) return PS4RF_ERR_PROTOCOL;
    if (ps4rf_canonical_bytes(hello, &hello_text, &hello_len, &err) != PS4RF_OK) return PS4RF_ERR_PROTOCOL;
    if (ps4rf_canonical_bytes(ack, &ack_text, &ack_len, &err) != PS4RF_OK) {
        free(hello_text);
        return PS4RF_ERR_PROTOCOL;
    }
    st = ps4rf_transcript_hash(hello_text, hello_len, ack_text, ack_len, transcript);
    free(hello_text);
    free(ack_text);
    if (st != PS4RF_OK) return st;
    st = ps4rf_derive_keys(psk, agent_nonce, host_nonce, transcript, &out->keys);
    if (st != PS4RF_OK) return st;
    st = ps4rf_nonce_prefix(psk, agent_nonce, host_nonce, transcript, PS4RF_DIR_AGENT_TO_HOST, out->pfx_a2h);
    if (st != PS4RF_OK) return st;
    st = ps4rf_nonce_prefix(psk, agent_nonce, host_nonce, transcript, PS4RF_DIR_HOST_TO_AGENT, out->pfx_h2a);
    if (st != PS4RF_OK) return st;
    sid = jval_string(jval_get(ack, "session_id"), NULL);
    if (sid == NULL || strlen(sid) >= sizeof(out->session_id)) return PS4RF_ERR_PROTOCOL;
    memcpy(out->session_id, sid, strlen(sid) + 1u);
    return PS4RF_OK;
}

/* W14 §2: session key material, the nonce prefixes and the session id are wiped before
 * `ps4rf_agent_run` returns -- whichever way it returns. Every exit path after the keys exist
 * goes through this helper, and a source gate asserts that. */
static ps4rf_agent_result agent_finish(ps4rf_session_keys *sk, ps4rf_agent_result result)
{
    if (sk != NULL) {
        volatile unsigned char *p = (volatile unsigned char *)sk;
        size_t n = sizeof(*sk);
        while (n-- > 0u) *p++ = 0u;
    }
    return result;
}

static int send_frame_obj(int fd, ps4rf_channel *ch, const char *mtype, const jval *obj, int allow_reserved)
{
    char *canon = NULL;
    size_t canon_len = 0u;
    const char *err = NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0u;
    int rc;
    if (ps4rf_canonical_bytes(obj, &canon, &canon_len, &err) != PS4RF_OK) return -1;
    if (ps4rf_frame_encode(ch, mtype, (const uint8_t *)canon, canon_len, &wire, &wire_len, allow_reserved) != PS4RF_OK) {
        free(canon);
        return -1;
    }
    rc = write_all(fd, wire, wire_len);
    free(canon);
    free(wire);
    return rc;
}

static void bye_cleanup_object(char *out, size_t cap, unsigned state_kind)
{
    /* "COMPLETE" when nothing is held, "PARTIAL" when objects outlived the session. */
    const char *state = state_kind == 0u ? "COMPLETE" : "PARTIAL";
    size_t n = 0u;
    const char *p = state;
    out[0] = '\0';
    while (*p != '\0' && n + 1u < cap) out[n++] = *p++;
    out[n] = '\0';
}

static void send_bye(int fd, ps4rf_channel *ch, const char *reason, const ps4rf_rt *rt)
{
    jval *bye = jval_new_object();
    jval *cleanup = jval_new_object();
    jval *resources = jval_new_array();
    char state[16];
    if (bye == NULL || cleanup == NULL || resources == NULL) {
        jval_free(bye);
        jval_free(cleanup);
        jval_free(resources);
        return;
    }
    bye_cleanup_object(state, sizeof(state), ps4rf_res_live(&rt->res) > 0u ? 1u : 0u);
    if (jval_obj_set(cleanup, "state", jval_new_string(state)) != 0 ||
        jval_obj_set(cleanup, "resources", resources) != 0 ||
        jval_obj_set(bye, "cleanup", cleanup) != 0 ||
        jval_obj_set(bye, "msg", jval_new_string("BYE")) != 0 ||
        jval_obj_set(bye, "reason", jval_new_string(reason)) != 0) {
        jval_free(bye);
        return;
    }
    (void)send_frame_obj(fd, ch, "BYE", bye, 0);
    jval_free(bye);
}

/* ------------------------------------------------------------------- session */

ps4rf_agent_result ps4rf_agent_run(int fd, const uint8_t psk[32], const char *label,
                                   const char *context, const char *provider_id,
                                   const ps4rf_agent_identity *identity, ps4rf_rt *rt,
                                   char *bye_reason_out, size_t bye_reason_cap)
{
    const char *build_id = (identity != NULL && identity->build_id != NULL)
                           ? identity->build_id : "unresolved";
    const ps4rf_platform *pf = ps4rf_platform_get();
    jval *hello = NULL;
    jval *ack = NULL;
    ps4rf_session_keys sk;
    ps4rf_channel out_ch, in_ch;
    ps4rf_status st;
    uint64_t start_us;
    uint64_t last_activity_us;
    uint32_t protocol_version = 1u;
    ps4rf_agent_result result = PS4RF_AGENT_RAN;
    const char *bye_reason = "CLIENT_CLOSE";
#ifdef PS4RF_TARGET_ATTEST
    int attest_done = 0;
#endif
#ifdef PS4RF_TARGET_BOOTID
    int boot_done = 0;
#endif
#ifdef PS4RF_TARGET_BOOTREAD
    int bootread_done = 0;
#endif
    /* W14: one re-arm of the privileged one shot per session -- session setup, never a request.
     * The provider refuses a second read inside the same session structurally. */
    ps4rf_stub_session_begin();

    memset(&sk, 0, sizeof(sk));
    memset(&out_ch, 0, sizeof(out_ch));
    memset(&in_ch, 0, sizeof(in_ch));
    if (bye_reason_out != NULL && bye_reason_cap > 0u) bye_reason_out[0] = '\0';

    hello = build_hello(label, context, provider_id, identity);
    if (hello == NULL) return agent_finish(&sk, PS4RF_AGENT_HELLO_FAILED);
    st = ps4rf_agent_handshake(fd, psk, hello, &sk.keys, &ack);
    if (st != PS4RF_OK) {
        jval_free(hello);
        jval_free(ack);
        return agent_finish(&sk, PS4RF_AGENT_HANDSHAKE_FAILED);
    }
    st = derive_session(psk, hello, ack, &sk);
    jval_free(hello);
    if (st != PS4RF_OK) {
        jval_free(ack);
        return agent_finish(&sk, PS4RF_AGENT_HANDSHAKE_FAILED);
    }
    {
        const jval *pv = jval_get(ack, "protocol_version");
        if (pv != NULL && jval_kind(pv) == JVAL_INT) protocol_version = (uint32_t)jval_int(pv);
    }
    jval_free(ack);

    {
        /* Bounds are set by the caller before the call and survive the runtime reset
         * (the console payload and the host build choose their own budgets). */
        unsigned want_lifetime = rt->lifetime_s;
        unsigned want_idle = rt->idle_s;
        ps4rf_rt_init(rt, sk.session_id, build_id, context, provider_id);
        if (want_lifetime > 0u) rt->lifetime_s = want_lifetime;
        if (want_idle > 0u) rt->idle_s = want_idle;
    }
    /* §11/W14: the recovery flag is boot-wide, so every *new* session starts with it -- a fresh
     * runtime would otherwise forget it. The router refuses mutating operations while it is set,
     * before any provider entry, and no session may clear it. */
    if (identity != NULL && identity->recovery_required) rt->recovery_required = 1;
    rt->protocol_version = protocol_version;

    if (ps4rf_channel_init(&out_ch, sk.keys.k_agent_to_host, sk.pfx_a2h, sk.session_id,
                           PS4RF_DIR_AGENT_TO_HOST, NULL, rt->max_frame_bytes, protocol_version) != PS4RF_OK) {
        return agent_finish(&sk, PS4RF_AGENT_PROTOCOL_FAILED);
    }
    if (ps4rf_channel_init(&in_ch, sk.keys.k_host_to_agent, sk.pfx_h2a, sk.session_id,
                           PS4RF_DIR_HOST_TO_AGENT, NULL, rt->max_frame_bytes, protocol_version) != PS4RF_OK) {
        return agent_finish(&sk, PS4RF_AGENT_PROTOCOL_FAILED);
    }

    /* Exactly one READY frame, sealed, carrying the measured target attestation. */
    {
        jval *ready = ps4rf_telemetry_ready_body(&rt->tel, rt->build_id, protocol_version,
                                                 rt->max_frame_bytes, rt->lifetime_s, rt->idle_s,
                                                 provider_id);
        if (ready == NULL) return agent_finish(&sk, PS4RF_AGENT_READY_FAILED);
        if (send_frame_obj(fd, &out_ch, "READY", ready, 1) != 0) {
            jval_free(ready);
            return agent_finish(&sk, PS4RF_AGENT_READY_FAILED);
        }
        jval_free(ready);
    }
    /* §4/W14: a session that opens while the boot is in recovery is in the recovery state from
     * the start -- the telemetry, the BYE and the evidence all report it. */
    rt->state = rt->recovery_required ? PS4RF_STATE_RECOVERY_REQUIRED : PS4RF_STATE_ACTIVE;

    start_us = pf->now_us();
    last_activity_us = start_us;

    for (;;) {
        uint8_t header[PS4RF_FRAME_HEADER_BYTES];
        char mtype[16];
        uint64_t seq = 0u;
        uint32_t ct_len = 0u;
        uint8_t *ct = NULL;
        uint8_t *pt = NULL;
        size_t pt_len = 0u;
        int io;

        /* W14: the resident checkpoint. At most one callback is installed (by a resident
         * caller); a non-zero answer ends the session and the caller owns the reason. */
        if (g_checkpoint != NULL && g_checkpoint(g_checkpoint_ctx) != 0) {
            bye_reason = "SERVER_CLOSE";
            result = PS4RF_AGENT_RAN;
            break;
        }

        if (pf->now_us() - start_us > (uint64_t)rt->lifetime_s * 1000000ull) {
            bye_reason = "SERVER_CLOSE";           /* lifetime bound of the W8 run */
            result = PS4RF_AGENT_RAN;
            break;
        }
        if (pf->now_us() - last_activity_us > (uint64_t)rt->idle_s * 1000000ull) {
            bye_reason = "SERVER_CLOSE";           /* idle bound */
            result = PS4RF_AGENT_RAN;
            break;
        }

        io = read_full(fd, header, sizeof(header));
        if (io == 1) break;                        /* peer closed: controlled exit */
        if (io < 0) {
            result = PS4RF_AGENT_IO_FAILED;
            bye_reason = "RECOVERY_REQUIRED";
            break;
        }
        last_activity_us = pf->now_us();
        if (ps4rf_frame_parse_header(header, rt->max_frame_bytes, mtype, &seq, &ct_len) != PS4RF_OK) {
            result = PS4RF_AGENT_PROTOCOL_FAILED;
            bye_reason = "RECOVERY_REQUIRED";
            break;
        }
        if (ps4rf_direction_check(PS4RF_DIR_AGENT_TO_HOST, mtype) != PS4RF_OK) {
            result = PS4RF_AGENT_PROTOCOL_FAILED;
            bye_reason = "RECOVERY_REQUIRED";
            break;
        }
        ct = (uint8_t *)malloc(ct_len == 0u ? 1u : (size_t)ct_len);
        pt = (uint8_t *)malloc((size_t)ct_len + 1u);
        if (ct == NULL || pt == NULL) {
            free(ct);
            free(pt);
            result = PS4RF_AGENT_IO_FAILED;
            bye_reason = "RECOVERY_REQUIRED";
            break;
        }
        if (read_full(fd, ct, ct_len) != 0) {
            free(ct);
            free(pt);
            result = PS4RF_AGENT_IO_FAILED;
            bye_reason = "RECOVERY_REQUIRED";
            break;
        }
        pt_len = ct_len;
        st = ps4rf_channel_open(&in_ch, mtype, seq, ct, ct_len, pt, &pt_len);
        free(ct);
        if (st != PS4RF_OK) {
            free(pt);
            result = PS4RF_AGENT_PROTOCOL_FAILED;
            bye_reason = "RECOVERY_REQUIRED";
            break;
        }
        {
            jval *request = jval_parse((const char *)pt, pt_len);
            free(pt);
            if (request == NULL) {
                result = PS4RF_AGENT_PROTOCOL_FAILED;
                bye_reason = "RECOVERY_REQUIRED";
                break;
            }
            rt->inflight = 1u;
            if (rt->inflight > rt->inflight_max_seen) rt->inflight_max_seen = rt->inflight;
            {
#if defined(PS4RF_TARGET_ATTEST) || defined(PS4RF_TARGET_BOOTID) || \
    defined(PS4RF_TARGET_BOOTREAD)
                /* Only the agent-side fixed steps need the operation name. In a build without
                 * them the extraction does not exist at all (no unused variable, no op name
                 * that could be matched by accident). */
                char request_op[64];
                size_t op_n = 0u;
                const jval *op_body = jval_get(request, "body");
                const char *op_str = (op_body != NULL && jval_kind(op_body) == JVAL_OBJECT)
                                         ? jval_string(jval_get(op_body, "operation"), NULL)
                                         : NULL;
                request_op[0] = '\0';
                while (op_str != NULL && op_str[op_n] != '\0' &&
                       op_n + 1u < sizeof(request_op)) {
                    request_op[op_n] = op_str[op_n];
                    op_n++;
                }
                request_op[op_n] = '\0';
#endif
                jval *response = NULL;
                ps4rf_route_outcome outcome = ps4rf_router_handle(rt, request, &response);
                rt->inflight = 0u;
                jval_free(request);
                if (outcome == PS4RF_ROUTE_OUTCOME_CLOSE) {
                    result = PS4RF_AGENT_PROTOCOL_FAILED;
                    bye_reason = "RECOVERY_REQUIRED";
                    break;
                }
                if (response == NULL) {
                    result = PS4RF_AGENT_PROTOCOL_FAILED;
                    bye_reason = "RECOVERY_REQUIRED";
                    break;
                }
                if (send_frame_obj(fd, &out_ch, "RESPONSE", response, 0) != 0) {
                    jval_free(response);
                    result = PS4RF_AGENT_IO_FAILED;
                    bye_reason = "RECOVERY_REQUIRED";
                    /* §5: the peer vanished while this answer was being written. Nothing is
                     * changed for a read-only operation; for a mutating one the outcome is
                     * unknown to the host, so the boot goes to recovery (never silently on). */
                    rt->undelivered_responses++;
                    if (rt->last_op_mutating) {
                        rt->undelivered_mutations++;
                        rt->recovery_required = 1;
                    }
                    break;
                }
                jval_free(response);
                /* §15: an authenticated admin shutdown was accepted in this request. The answer is
                 * on the wire first -- the controller must learn that its request was served, not
                 * that the connection dropped -- and then this session ends with its own bye. */
                if (rt->admin_shutdown) {
                    bye_reason = "ADMIN_SHUTDOWN";
                    break;
                }
#ifdef PS4RF_TARGET_ATTEST
                if (!attest_done && ps4rf_op_is(request_op, "session.status")) {
                    int run_status;
                    jval *event;
                    attest_done = 1;      /* before the call: no path can invoke it twice */
                    run_status = ps4rf_attest_run(&g_attest_info);
                    event = ps4rf_attest_event(&g_attest_info, run_status, rt->build_id, label);
                    if (event == NULL) {
                        result = PS4RF_AGENT_ATTEST_FAILED;
                        bye_reason = "ATTESTATION_FAILED";
                        break;
                    }
                    if (send_frame_obj(fd, &out_ch, "EVENT", event, 1) != 0) {
                        jval_free(event);
                        result = PS4RF_AGENT_IO_FAILED;
                        bye_reason = "RECOVERY_REQUIRED";
                        break;
                    }
                    jval_free(event);
                    if (run_status != PS4RF_ATTEST_RUN_OK) {
                        /* fail closed: the run ends here instead of continuing with a session
                         * whose attestation is unknown */
                        result = PS4RF_AGENT_ATTEST_FAILED;
                        bye_reason = "ATTESTATION_FAILED";
                        break;
                    }
                }
#endif
#ifdef PS4RF_TARGET_BOOTID
                if (!boot_done && ps4rf_op_is(request_op, "session.status")) {
                    int run_status;
                    jval *event;
                    boot_done = 1;        /* before the call: no path can collect twice */
                    run_status = ps4rf_boot_collect(&g_boot_info);
                    event = ps4rf_boot_event(&g_boot_info, rt->build_id, label);
                    if (event == NULL) {
                        result = PS4RF_AGENT_BOOT_FAILED;
                        bye_reason = "BOOT_EVENT_FAILED";
                        break;
                    }
                    if (send_frame_obj(fd, &out_ch, "EVENT", event, 1) != 0) {
                        jval_free(event);
                        result = PS4RF_AGENT_IO_FAILED;
                        bye_reason = "RECOVERY_REQUIRED";
                        break;
                    }
                    jval_free(event);
                    if (run_status != PS4RF_BOOT_RUN_OK) {
                        /* fail closed: the boot identity is unknown, unstable or implausible, so
                         * the session cannot be bound -- stop instead of pretending */
                        result = PS4RF_AGENT_BOOT_FAILED;
                        bye_reason = ps4rf_boot_status_name(run_status);
                        break;
                    }
                }
#endif
#ifdef PS4RF_TARGET_BOOTREAD
                if (!bootread_done && ps4rf_op_is(request_op, "session.status")) {
                    int run_status;
                    ps4rf_bootread_decoded dec;
                    jval *event;
                    long long wall = 0ll;
                    bootread_done = 1;    /* before the call: no path can invoke it twice */
                    if (pf->wall_sec != NULL && pf->wall_sec(&wall) != PS4RF_TF_OK) wall = 0ll;
                    run_status = ps4rf_bootread_run(&g_bootread_info, wall);
                    (void)ps4rf_bootread_decode(&g_bootread_info, &dec, wall);
                    event = ps4rf_bootread_event(&g_bootread_info, run_status, &dec, wall,
                                                 rt->build_id, label);
                    if (event == NULL) {
                        result = PS4RF_AGENT_BOOTREAD_FAILED;
                        bye_reason = "BOOTREAD_EVENT_FAILED";
                        break;
                    }
                    if (send_frame_obj(fd, &out_ch, "EVENT", event, 1) != 0) {
                        jval_free(event);
                        result = PS4RF_AGENT_IO_FAILED;
                        bye_reason = "RECOVERY_REQUIRED";
                        break;
                    }
                    jval_free(event);
                    if (run_status != PS4RF_BOOTREAD_RUN_OK) {
                        /* fail closed: no measured boot instant, no binding -- and the callback is
                         * never attempted a second time (the guard makes that structural) */
                        result = PS4RF_AGENT_BOOTREAD_FAILED;
                        bye_reason = ps4rf_bootread_bye_reason(run_status);
                        break;
                    }
                }
#endif
            }
        }
    }

    if (rt->ev.violations > 0u) {
        bye_reason = "RECOVERY_REQUIRED";
        rt->recovery_required = 1;
    }

    /* §2/§10: the session teardown. Whatever ended the session, it hands its resource set back
     * empty before the BYE reports the cleanup state -- a teardown that cannot do this (unbound or
     * inconsistent set) is a recovery condition, never a silent leak. */
    {
        unsigned reaped = 0u;
        ps4rf_res_status tst = ps4rf_res_teardown(&rt->res, &reaped);
        rt->cleanup_reaped = reaped;
        rt->cleanup_status = (int)tst;
        if (tst != PS4RF_RES_OK) {
            bye_reason = "RECOVERY_REQUIRED";
            rt->recovery_required = 1;
        }
    }

    rt->state = PS4RF_STATE_CLOSED;
    send_bye(fd, &out_ch, bye_reason, rt);

    if (bye_reason_out != NULL && bye_reason_cap > 0u) {
        size_t n = 0u;
        while (bye_reason[n] != '\0' && n + 1u < bye_reason_cap) {
            bye_reason_out[n] = bye_reason[n];
            n++;
        }
        bye_reason_out[n] = '\0';
    }
    /* §2/§14: the session's key material and session id die with the session, on every path. */
    return agent_finish(&sk, result);
}
