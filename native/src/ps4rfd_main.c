/* ps4rfd -- PS4RF agent, native userland skeleton (P4/W2, wire spec v1).
 *
 * Scope (W2): startup, connect-out transport (console -> operator host), AGENT
 * HELLO, HELLO_ACK parsing, transcript, HKDF, AUTH, AUTH_ACK validation,
 * directional AEAD channels, wire framing v1, sequence handling, a request
 * receive loop with two skeleton operations (session.ping, session.bye), clean
 * disconnect, fail-closed fatal protocol path.
 *
 * Deliberately absent: research primitives, kernel interaction, SDK use
 * (W0/D1, W0/D6, W2 item 10), event/ready frames (W0/D12).
 *
 * Usage:
 *   ps4rfd --connect HOST:PORT [--psk-hex HEX] [--agent-version V] [--label L]
 *          [--context C] [--provider P] [--transport T] [--timeout-ms N]
 *   ps4rfd --self-test-loopback     offline agent + host stub over a socket pair
 *                                   (TEST-ONLY session material, no network)
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "jcs.h"
#include "ps4rf_protocol.h"

#define PS4RFD_EXIT_OK 0
#define PS4RFD_EXIT_PROTOCOL 2
#define PS4RFD_EXIT_USAGE 3
#define PS4RFD_EXIT_IO 4

#define PS4RFD_SELFTEST_PSK_HEX \
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define PS4RFD_SELFTEST_SESSION_ID "SES-0123456789ABCDEF"
#define PS4RFD_SELFTEST_REQUEST_ID "REQ-00000000000000000000000000000001"

/* --------------------------------------------------------------- low level */

static int write_all_fd(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int read_exact_fd(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int random_bytes(uint8_t *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;
    if (f == NULL) return -1;
    got = fread(out, 1, len, f);
    fclose(f);
    return got == len ? 0 : -1;
}

static const char *get_str(const jval *obj, const char *key)
{
    const jval *v = obj == NULL ? NULL : jval_get(obj, key);
    if (v == NULL || jval_kind(v) != JVAL_STRING) return NULL;
    return jval_string(v, NULL);
}

/* --------------------------------------------------------------- objects */

/* Field set and types mirror the pinned HELLO vector; the values are agent-local. */
static jval *build_hello(const char *agent_version, const char *label, const char *context,
                         const char *provider, const char *transport)
{
    uint8_t nonce[16];
    char nonce_hex[33];
    jval *hello;
    if (random_bytes(nonce, sizeof(nonce)) != 0) return NULL;
    ps4rf_hex_encode(nonce, sizeof(nonce), nonce_hex);
    hello = jval_new_object();
    if (hello == NULL) return NULL;
    if (jval_obj_set(hello, "agent_version", jval_new_string(agent_version)) != 0 ||
        jval_obj_set(hello, "context", jval_new_string(context)) != 0 ||
        jval_obj_set(hello, "label", jval_new_string(label)) != 0 ||
        jval_obj_set(hello, "msg", jval_new_string("HELLO")) != 0 ||
        jval_obj_set(hello, "nonce", jval_new_string(nonce_hex)) != 0 ||
        jval_obj_set(hello, "provider", jval_new_string(provider)) != 0 ||
        jval_obj_set(hello, "recovery_required", jval_new_bool(0)) != 0 ||
        jval_obj_set(hello, "transport", jval_new_string(transport)) != 0) {
        jval_free(hello);
        return NULL;
    }
    return hello;
}

/* Mirrors the pinned HELLO_ACK vector field set; used by the self-test stub and
 * available to the agent for offline runs (the operator host supplies the real one). */
static jval *build_hello_ack(const char *session_id, uint32_t protocol_version)
{
    uint8_t nonce[16];
    char nonce_hex[33];
    jval *limits = jval_new_object();
    jval *ack = jval_new_object();
    if (limits == NULL || ack == NULL || random_bytes(nonce, sizeof(nonce)) != 0) {
        jval_free(limits);
        jval_free(ack);
        return NULL;
    }
    ps4rf_hex_encode(nonce, sizeof(nonce), nonce_hex);
    if (jval_obj_set(limits, "max_chunk_bytes", jval_new_int(1048576)) != 0 ||
        jval_obj_set(limits, "max_ir_bytes", jval_new_int(262144)) != 0 ||
        jval_obj_set(ack, "aead", jval_new_string("AEAD_CHACHA20_POLY1305")) != 0 ||
        jval_obj_set(ack, "auth_required", jval_new_bool(1)) != 0 ||
        jval_obj_set(ack, "limits", limits) != 0 ||
        jval_obj_set(ack, "msg", jval_new_string("HELLO_ACK")) != 0 ||
        jval_obj_set(ack, "nonce", jval_new_string(nonce_hex)) != 0 ||
        jval_obj_set(ack, "protocol_version", jval_new_int((int64_t)protocol_version)) != 0 ||
        jval_obj_set(ack, "session_id", jval_new_string(session_id)) != 0) {
        jval_free(ack);
        return NULL;
    }
    return ack;
}

static jval *make_ping_response(const char *request_id)
{
    jval *header = jval_new_object();
    jval *resp = jval_new_object();
    if (header == NULL || resp == NULL) {
        jval_free(header);
        jval_free(resp);
        return NULL;
    }
    if (jval_obj_set(header, "in_reply_to", jval_new_string(request_id)) != 0 ||
        jval_obj_set(resp, "header", header) != 0 ||
        jval_obj_set(resp, "result", jval_new_object()) != 0 ||
        jval_obj_set(resp, "status", jval_new_string("OK")) != 0) {
        jval_free(resp);
        return NULL;
    }
    return resp;
}

static jval *make_error_response(const char *request_id, const char *code)
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
    if (jval_obj_set(header, "in_reply_to", jval_new_string(request_id)) != 0 ||
        jval_obj_set(error, "code", jval_new_string(code)) != 0 ||
        jval_obj_set(resp, "error", error) != 0 ||
        jval_obj_set(resp, "header", header) != 0 ||
        jval_obj_set(resp, "status", jval_new_string("ERROR")) != 0) {
        jval_free(resp);
        return NULL;
    }
    return resp;
}

static jval *make_bye(void)
{
    jval *cleanup = jval_new_object();
    jval *bye = jval_new_object();
    if (cleanup == NULL || bye == NULL) {
        jval_free(cleanup);
        jval_free(bye);
        return NULL;
    }
    if (jval_obj_set(cleanup, "resources", jval_new_array()) != 0 ||
        jval_obj_set(cleanup, "state", jval_new_string("COMPLETE")) != 0 ||
        jval_obj_set(bye, "cleanup", cleanup) != 0 ||
        jval_obj_set(bye, "msg", jval_new_string("BYE")) != 0 ||
        jval_obj_set(bye, "reason", jval_new_string("CLIENT_CLOSE")) != 0) {
        jval_free(bye);
        return NULL;
    }
    return bye;
}

/* --------------------------------------------------------------- session */

typedef struct {
    uint8_t psk[32];
    uint8_t agent_nonce[16];
    uint8_t host_nonce[16];
    uint8_t transcript[32];
    ps4rf_keys keys;
    uint8_t pfx_a2h[4];
    uint8_t pfx_h2a[4];
    char session_id[64];
} agent_session;

static int nonce_from(const jval *obj, uint8_t out[16])
{
    const char *hex = get_str(obj, "nonce");
    return hex != NULL && ps4rf_hex_decode(hex, out, 16, NULL) == PS4RF_OK ? 0 : -1;
}

/* Derives transcript, keys and nonce prefixes from the two handshake objects;
 * both peers run this and must arrive at identical material. */
static ps4rf_status session_from_handshake(const uint8_t psk[32], const jval *hello,
                                           const jval *ack, agent_session *out)
{
    char *hello_text = NULL, *ack_text = NULL;
    size_t hello_len = 0, ack_len = 0;
    ps4rf_status st;

    if (hello == NULL || ack == NULL || out == NULL) return PS4RF_ERR_PROTOCOL;
    memset(out, 0, sizeof(*out));
    memcpy(out->psk, psk, 32);
    if (nonce_from(hello, out->agent_nonce) != 0 || nonce_from(ack, out->host_nonce) != 0)
        return PS4RF_ERR_PROTOCOL;
    if (jcs_serialize(hello, &hello_text, &hello_len) != 0) return PS4RF_ERR_PROTOCOL;
    if (jcs_serialize(ack, &ack_text, &ack_len) != 0) {
        free(hello_text);
        return PS4RF_ERR_PROTOCOL;
    }
    st = ps4rf_transcript_hash(hello_text, hello_len, ack_text, ack_len, out->transcript);
    free(hello_text);
    free(ack_text);
    if (st != PS4RF_OK) return st;
    st = ps4rf_derive_keys(out->psk, out->agent_nonce, out->host_nonce, out->transcript,
                           &out->keys);
    if (st != PS4RF_OK) return st;
    st = ps4rf_nonce_prefix(out->psk, out->agent_nonce, out->host_nonce, out->transcript,
                            PS4RF_DIR_AGENT_TO_HOST, out->pfx_a2h);
    if (st != PS4RF_OK) return st;
    st = ps4rf_nonce_prefix(out->psk, out->agent_nonce, out->host_nonce, out->transcript,
                            PS4RF_DIR_HOST_TO_AGENT, out->pfx_h2a);
    if (st != PS4RF_OK) return st;
    {
        const char *sid = get_str(ack, "session_id");
        if (sid == NULL || strlen(sid) >= sizeof(out->session_id)) return PS4RF_ERR_PROTOCOL;
        memcpy(out->session_id, sid, strlen(sid) + 1);
    }
    return PS4RF_OK;
}

static ps4rf_status send_reply_frame(int fd, ps4rf_channel *out_ch, const char *mtype,
                                     const jval *reply)
{
    char *canon = NULL;
    size_t canon_len = 0;
    const char *err = NULL;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ps4rf_status st = ps4rf_canonical_bytes(reply, &canon, &canon_len, &err);
    if (st != PS4RF_OK) return st;
    st = ps4rf_frame_encode(out_ch, mtype, (const uint8_t *)canon, canon_len, &wire, &wire_len, 0);
    free(canon);
    if (st != PS4RF_OK) return st;
    if (write_all_fd(fd, wire, wire_len) != 0) st = PS4RF_ERR_PROTOCOL;
    free(wire);
    return st;
}

/* Skeleton request handling. Unknown operations answer with the pinned ERROR
 * shape (code UNSUPPORTED_OPERATION); nothing else is invented. */
static ps4rf_status handle_request(int fd, ps4rf_channel *out_ch, const uint8_t *payload,
                                   size_t payload_len, int *should_close)
{
    jval *req = jval_parse((const char *)payload, payload_len);
    const jval *header, *body;
    const char *request_id = NULL, *operation = NULL;
    jval *reply = NULL;
    ps4rf_status st;

    *should_close = 0;
    if (req == NULL) return PS4RF_ERR_PARSE;
    header = jval_get(req, "header");
    body = jval_get(req, "body");
    if (header != NULL) request_id = get_str(header, "request_id");
    if (body != NULL) operation = get_str(body, "operation");
    if (request_id == NULL || operation == NULL) {
        jval_free(req);
        return PS4RF_ERR_PROTOCOL;
    }
    if (strcmp(operation, "session.ping") == 0) {
        reply = make_ping_response(request_id);
    } else if (strcmp(operation, "session.bye") == 0) {
        reply = make_bye();
        *should_close = 1;
    } else {
        reply = make_error_response(request_id, "UNSUPPORTED_OPERATION");
    }
    jval_free(req);
    if (reply == NULL) return PS4RF_ERR_PROTOCOL;
    st = send_reply_frame(fd, out_ch, *should_close ? "BYE" : "RESPONSE", reply);
    jval_free(reply);
    return st;
}

/* Returns PS4RF_OK for a clean disconnect, otherwise the fatal protocol failure. */
static ps4rf_status run_session(int fd, const agent_session *sess)
{
    ps4rf_channel out_ch, in_ch;
    ps4rf_status st = ps4rf_channel_init(&out_ch, sess->keys.k_agent_to_host, sess->pfx_a2h,
                                         sess->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                                         PS4RF_MAX_FRAME_BYTES_DEFAULT, 1);
    if (st != PS4RF_OK) return st;
    st = ps4rf_channel_init(&in_ch, sess->keys.k_host_to_agent, sess->pfx_h2a, sess->session_id,
                            PS4RF_DIR_HOST_TO_AGENT, NULL, PS4RF_MAX_FRAME_BYTES_DEFAULT, 1);
    if (st != PS4RF_OK) return st;

    for (;;) {
        uint8_t header[PS4RF_FRAME_HEADER_BYTES];
        char mtype[16];
        uint64_t seq = 0;
        uint32_t ct_len = 0;
        uint8_t *ct = NULL;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        int should_close = 0;

        if (read_exact_fd(fd, header, sizeof(header)) != 0) return PS4RF_OK; /* peer closed */
        st = ps4rf_frame_parse_header(header, PS4RF_MAX_FRAME_BYTES_DEFAULT, mtype, &seq, &ct_len);
        if (st != PS4RF_OK) return st;
        st = ps4rf_direction_check(PS4RF_DIR_AGENT_TO_HOST, mtype);
        if (st != PS4RF_OK) return st;
        ct = (uint8_t *)malloc(ct_len == 0 ? 1 : ct_len);
        pt = (uint8_t *)malloc(ct_len + 1);
        if (ct == NULL || pt == NULL) {
            free(ct);
            free(pt);
            return PS4RF_ERR_PROTOCOL;
        }
        if (read_exact_fd(fd, ct, ct_len) != 0) {
            free(ct);
            free(pt);
            return PS4RF_ERR_PROTOCOL;
        }
        pt_len = ct_len; /* capacity for the AEAD open */
        st = ps4rf_channel_open(&in_ch, mtype, seq, ct, ct_len, pt, &pt_len);
        free(ct);
        if (st != PS4RF_OK) {
            free(pt);
            return st;
        }
        st = handle_request(fd, &out_ch, pt, pt_len, &should_close);
        free(pt);
        if (st != PS4RF_OK) return st;
        if (should_close) return PS4RF_OK; /* clean disconnect after BYE */
    }
}

/* --------------------------------------------------------------- transport */

static int connect_out(const char *host, const char *port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL, *it;
    int fd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (it = res; it != NULL; it = it->ai_next) {
        int flags;
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            fcntl(fd, F_SETFL, flags);
            break;
        }
        if (errno == EINPROGRESS) {
            struct pollfd pfd;
            int rc;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            rc = poll(&pfd, 1, timeout_ms);
            if (rc == 1) {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                if (soerr == 0) {
                    fcntl(fd, F_SETFL, flags);
                    break;
                }
            }
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static ps4rf_status agent_run(int fd, const uint8_t psk[32], const char *agent_version,
                              const char *label, const char *context, const char *provider,
                              const char *transport, agent_session *out_sess, int *clean)
{
    jval *hello = build_hello(agent_version, label, context, provider, transport);
    jval *ack = NULL;
    ps4rf_keys keys;
    ps4rf_status st;

    *clean = 0;
    if (hello == NULL) return PS4RF_ERR_PROTOCOL;
    st = ps4rf_agent_handshake(fd, psk, hello, &keys, &ack);
    if (st != PS4RF_OK) {
        jval_free(hello);
        return st;
    }
    st = session_from_handshake(psk, hello, ack, out_sess);
    jval_free(hello);
    jval_free(ack);
    if (st != PS4RF_OK) return st;
    if (memcmp(&keys.k_hs, &out_sess->keys.k_hs, 32) != 0) {
        fprintf(stderr, "ps4rfd: handshake and session keys disagree\n");
        return PS4RF_ERR_PROTOCOL;
    }
    st = run_session(fd, out_sess);
    if (st == PS4RF_OK) *clean = 1;
    return st;
}

/* --------------------------------------------------------- self-test stub */

typedef struct {
    int fd;
    uint8_t psk[32];
    jval *ack;
    jval *hello; /* filled by the handshake */
    ps4rf_status status;
    char detail[256];
    int saw_ping_response;
    int saw_bye;
    agent_session sess;
    int have_sess;
} stub_ctx;

static void stub_fail(stub_ctx *c, const char *detail)
{
    c->status = PS4RF_ERR_PROTOCOL;
    snprintf(c->detail, sizeof(c->detail), "%s", detail);
}

static void *stub_main(void *arg)
{
    stub_ctx *c = (stub_ctx *)arg;
    agent_session sess;
    ps4rf_channel out_ch, in_ch;
    ps4rf_status st;

    c->status = PS4RF_OK;
    snprintf(c->detail, sizeof(c->detail), "ok");

    st = ps4rf_host_handshake(c->fd, c->psk, c->ack, NULL, &c->hello);
    if (st != PS4RF_OK) {
        stub_fail(c, "host handshake rejected the agent");
        close(c->fd);
        return NULL;
    }
    st = session_from_handshake(c->psk, c->hello, c->ack, &sess);
    if (st != PS4RF_OK) {
        stub_fail(c, "host could not derive the session");
        close(c->fd);
        return NULL;
    }
    c->sess = sess;
    c->have_sess = 1;
    if (ps4rf_channel_init(&out_ch, sess.keys.k_host_to_agent, sess.pfx_h2a, sess.session_id,
                           PS4RF_DIR_HOST_TO_AGENT, NULL, PS4RF_MAX_FRAME_BYTES_DEFAULT, 1) !=
            PS4RF_OK ||
        ps4rf_channel_init(&in_ch, sess.keys.k_agent_to_host, sess.pfx_a2h, sess.session_id,
                           PS4RF_DIR_AGENT_TO_HOST, NULL, PS4RF_MAX_FRAME_BYTES_DEFAULT, 1) !=
            PS4RF_OK) {
        stub_fail(c, "host channel setup failed");
        close(c->fd);
        return NULL;
    }

    /* one REQUEST/session.ping round trip, then one REQUEST/session.bye */
    {
        const char *requests[2] = {"session.ping", "session.bye"};
        const char *expect_reply[2] = {"RESPONSE", "BYE"};
        int i;
        for (i = 0; i < 2; i++) {
            jval *header = jval_new_object();
            jval *body = jval_new_object();
            jval *req = jval_new_object();
            char *canon = NULL;
            size_t canon_len = 0;
            const char *err = NULL;
            uint8_t *wire = NULL;
            size_t wire_len = 0;
            uint8_t rheader[PS4RF_FRAME_HEADER_BYTES];
            char rmtype[16];
            uint64_t rseq = 0;
            uint32_t rlen = 0;
            uint8_t *rct = NULL, *rpt = NULL;
            size_t rpt_len = 0;

            jval_obj_set(header, "request_id", jval_new_string(PS4RFD_SELFTEST_REQUEST_ID));
            jval_obj_set(body, "arguments", jval_new_object());
            jval_obj_set(body, "operation", jval_new_string(requests[i]));
            jval_obj_set(req, "body", body);
            jval_obj_set(req, "header", header);
            if (ps4rf_canonical_bytes(req, &canon, &canon_len, &err) != PS4RF_OK ||
                ps4rf_frame_encode(&out_ch, "REQUEST", (const uint8_t *)canon, canon_len, &wire,
                                   &wire_len, 0) != PS4RF_OK ||
                write_all_fd(c->fd, wire, wire_len) != 0) {
                free(canon);
                free(wire);
                jval_free(req);
                stub_fail(c, "host stub could not send a REQUEST");
                close(c->fd);
                return NULL;
            }
            free(canon);
            free(wire);
            jval_free(req);

            if (read_exact_fd(c->fd, rheader, sizeof(rheader)) != 0 ||
                ps4rf_frame_parse_header(rheader, PS4RF_MAX_FRAME_BYTES_DEFAULT, rmtype, &rseq,
                                         &rlen) != PS4RF_OK) {
                stub_fail(c, "host stub could not read the reply header");
                close(c->fd);
                return NULL;
            }
            rct = (uint8_t *)malloc(rlen == 0 ? 1 : rlen);
            rpt = (uint8_t *)malloc(rlen + 1);
            rpt_len = rlen; /* capacity for the AEAD open */
            if (rct == NULL || rpt == NULL || read_exact_fd(c->fd, rct, rlen) != 0 ||
                ps4rf_channel_open(&in_ch, rmtype, rseq, rct, rlen, rpt, &rpt_len) != PS4RF_OK) {
                free(rct);
                free(rpt);
                stub_fail(c, "host stub could not open the reply frame");
                close(c->fd);
                return NULL;
            }
            free(rct);
            if (strcmp(rmtype, expect_reply[i]) != 0) {
                free(rpt);
                stub_fail(c, "unexpected reply message type");
                close(c->fd);
                return NULL;
            }
            {
                jval *reply = jval_parse((const char *)rpt, rpt_len);
                free(rpt);
                if (reply == NULL) {
                    stub_fail(c, "reply payload was not JSON");
                    close(c->fd);
                    return NULL;
                }
                if (i == 0) {
                    const char *status = get_str(reply, "status");
                    const jval *rh = jval_get(reply, "header");
                    const char *rid = rh == NULL ? NULL : get_str(rh, "in_reply_to");
                    c->saw_ping_response = status != NULL && strcmp(status, "OK") == 0 &&
                                           rid != NULL &&
                                           strcmp(rid, PS4RFD_SELFTEST_REQUEST_ID) == 0;
                } else {
                    const jval *cleanup = jval_get(reply, "cleanup");
                    const char *msg = get_str(reply, "msg");
                    const char *state = cleanup == NULL ? NULL : get_str(cleanup, "state");
                    c->saw_bye = msg != NULL && strcmp(msg, "BYE") == 0 && state != NULL &&
                                 strcmp(state, "COMPLETE") == 0;
                }
                jval_free(reply);
            }
        }
    }
    if (!c->saw_ping_response) {
        stub_fail(c, "ping response did not match the pinned RESPONSE shape");
    } else if (!c->saw_bye) {
        stub_fail(c, "BYE did not match the pinned BYE shape");
    }
    /* read to EOF so the agent sees a clean close */
    {
        uint8_t byte;
        while (read(c->fd, &byte, 1) > 0) {
        }
    }
    close(c->fd);
    return NULL;
}

static int self_test_loopback(void)
{
    uint8_t psk[32];
    int fds[2];
    pthread_t thread;
    stub_ctx ctx;
    agent_session sess;
    ps4rf_status st;
    int clean = 0;
    int rc = PS4RFD_EXIT_OK;

    fprintf(stderr,
            "ps4rfd: self-test loopback uses TEST-ONLY session material and never opens a "
            "network socket\n");
    if (ps4rf_hex_decode(PS4RFD_SELFTEST_PSK_HEX, psk, sizeof(psk), NULL) != PS4RF_OK)
        return PS4RFD_EXIT_USAGE;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return PS4RFD_EXIT_IO;

    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = fds[1];
    memcpy(ctx.psk, psk, sizeof(psk));
    ctx.ack = build_hello_ack(PS4RFD_SELFTEST_SESSION_ID, 1);
    if (ctx.ack == NULL) return PS4RFD_EXIT_USAGE;
    if (pthread_create(&thread, NULL, stub_main, &ctx) != 0) return PS4RFD_EXIT_IO;

    st = agent_run(fds[0], psk, "ps4rfd-0.1.0-w2", PS4RF_HANDSHAKE_LABEL, "ps4-skeleton",
                   "ps4rfd", "loopback", &sess, &clean);
    close(fds[0]); /* the stub waits for EOF, so close before joining */
    pthread_join(thread, NULL);

    printf("self-test loopback\n");
    printf("  agent handshake:      %s\n", st == PS4RF_OK ? "OK" : ps4rf_status_name(st));
    printf("  clean disconnect:     %s\n", clean ? "yes" : "no");
    printf("  host stub:            %s (%s)\n", ctx.status == PS4RF_OK ? "OK" : "FAILED",
           ctx.detail);
    printf("  session id:           %s\n", sess.session_id[0] != '\0' ? sess.session_id : "-");
    {
        char hex[65], stub_hex[65], pfx_hex[9], stub_pfx[9];
        ps4rf_hex_encode(sess.keys.k_hs, 32, hex);
        printf("  k_hs:                 %s\n", hex);
        if (ctx.have_sess) {
            ps4rf_hex_encode(ctx.sess.keys.k_hs, 32, stub_hex);
            ps4rf_hex_encode(sess.pfx_h2a, 4, pfx_hex);
            ps4rf_hex_encode(ctx.sess.pfx_h2a, 4, stub_pfx);
            printf("  both sides agree:     k_hs %s, host->agent prefix %s\n",
                   strcmp(hex, stub_hex) == 0 ? "yes" : "NO", strcmp(pfx_hex, stub_pfx) == 0 ? "yes" : "NO");
            if (strcmp(hex, stub_hex) != 0) printf("  host-side k_hs:       %s\n", stub_hex);
        }
    }
    printf("  ping response:        %s\n", ctx.saw_ping_response ? "verified" : "MISSING");
    printf("  BYE + cleanup:        %s\n", ctx.saw_bye ? "verified" : "MISSING");

    if (st != PS4RF_OK) {
        fprintf(stderr, "ps4rfd: agent side failed: %s\n", ps4rf_status_name(st));
        rc = PS4RFD_EXIT_PROTOCOL;
    } else if (!clean || ctx.status != PS4RF_OK || !ctx.saw_ping_response || !ctx.saw_bye) {
        rc = PS4RFD_EXIT_PROTOCOL;
    } else {
        printf("  verdict:              PASS\n");
    }
    jval_free(ctx.ack);
    jval_free(ctx.hello);
    return rc;
}

/* -------------------------------------------------------------------- main */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s --connect HOST:PORT [--psk-hex HEX] [--agent-version V] [--label L]\n"
            "          [--context C] [--provider P] [--transport T] [--timeout-ms N]\n"
            "       %s --self-test-loopback\n",
            argv0, argv0);
}

int main(int argc, char **argv)
{
    const char *connect_arg = NULL;
    const char *psk_hex = getenv("PS4RF_PSK_HEX");
    const char *agent_version = "ps4rfd-0.1.0-w2";
    const char *label = PS4RF_HANDSHAKE_LABEL;
    const char *context = "ps4-skeleton";
    const char *provider = "ps4rfd";
    const char *transport = "tcp";
    int timeout_ms = 10000;
    int i;
    uint8_t psk[32];
    agent_session sess;
    int fd;
    char host[256];
    char port[16];
    const char *colon;

    signal(SIGPIPE, SIG_IGN);
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test-loopback") == 0) return self_test_loopback();
        if (strcmp(argv[i], "--connect") == 0 && i + 1 < argc) connect_arg = argv[++i];
        else if (strcmp(argv[i], "--psk-hex") == 0 && i + 1 < argc) psk_hex = argv[++i];
        else if (strcmp(argv[i], "--agent-version") == 0 && i + 1 < argc) agent_version = argv[++i];
        else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) label = argv[++i];
        else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) context = argv[++i];
        else if (strcmp(argv[i], "--provider") == 0 && i + 1 < argc) provider = argv[++i];
        else if (strcmp(argv[i], "--transport") == 0 && i + 1 < argc) transport = argv[++i];
        else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else {
            usage(argv[0]);
            return PS4RFD_EXIT_USAGE;
        }
    }
    if (connect_arg == NULL) {
        usage(argv[0]);
        return PS4RFD_EXIT_USAGE;
    }
    if (psk_hex == NULL || ps4rf_hex_decode(psk_hex, psk, sizeof(psk), NULL) != PS4RF_OK) {
        fprintf(stderr, "ps4rfd: a 32-byte --psk-hex (or PS4RF_PSK_HEX) is required\n");
        return PS4RFD_EXIT_USAGE;
    }
    colon = strrchr(connect_arg, ':');
    if (colon == NULL || (size_t)(colon - connect_arg) >= sizeof(host)) {
        fprintf(stderr, "ps4rfd: --connect expects HOST:PORT\n");
        return PS4RFD_EXIT_USAGE;
    }
    memcpy(host, connect_arg, (size_t)(colon - connect_arg));
    host[colon - connect_arg] = '\0';
    snprintf(port, sizeof(port), "%s", colon + 1);

    fd = connect_out(host, port, timeout_ms);
    if (fd < 0) {
        fprintf(stderr, "ps4rfd: connect-out to %s failed: %s\n", connect_arg, strerror(errno));
        return PS4RFD_EXIT_IO;
    }
    {
        int clean = 0;
        ps4rf_status st = agent_run(fd, psk, agent_version, label, context, provider, transport,
                                    &sess, &clean);
        close(fd);
        if (st != PS4RF_OK) {
            fprintf(stderr, "ps4rfd: fatal protocol failure: %s\n", ps4rf_status_name(st));
            return PS4RFD_EXIT_PROTOCOL;
        }
        printf("ps4rfd: session %s closed cleanly\n", sess.session_id);
        return PS4RFD_EXIT_OK;
    }
}
