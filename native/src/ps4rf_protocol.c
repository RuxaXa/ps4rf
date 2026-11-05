/* PS4RF native protocol core -- implementation. Mirrors the frozen Python
 * reference byte for byte (core/rpc/handshake.py, core/rpc/wire.py,
 * core/canonical.py). See ps4rf_protocol.h for the contract. */

#include "ps4rf_protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chacha20poly1305.h"
#include "sha256.h"

/* --------------------------------------------------------------- diagnostics */

const char *ps4rf_status_name(ps4rf_status status)
{
    switch (status) {
    case PS4RF_OK:                  return "";
    case PS4RF_ERR_PROTOCOL:        return "ProtocolError";
    case PS4RF_ERR_REPLAY:          return "ReplayDetected";
    case PS4RF_ERR_SEQ_EXHAUSTED:   return "SequenceExhausted";
    case PS4RF_ERR_FRAME_LIMIT:     return "FrameLimitExceeded";
    case PS4RF_ERR_AUTH_FAILED:     return "AuthenticationFailed";
    case PS4RF_ERR_UNKNOWN_TYPE:    return "UnknownFrameType";
    case PS4RF_ERR_RESERVED_TYPE:   return "ReservedFrameType";
    case PS4RF_ERR_UNSAFE_NUMBER:   return "UnsafeNumber";
    case PS4RF_ERR_TYPE:            return "TypeError";
    case PS4RF_ERR_PARSE:           return "ProtocolError"; /* JSON errors surface as protocol errors */
    case PS4RF_ERR_LIMIT:           return "ProtocolError";
    default:                        return "ProtocolError";
    }
}

const char *ps4rf_direction_string(ps4rf_direction dir)
{
    return dir == PS4RF_DIR_AGENT_TO_HOST ? "Direction.AGENT_TO_HOST" : "Direction.HOST_TO_AGENT";
}

ps4rf_status ps4rf_status_from_error_name(const char *error_name)
{
    if (error_name == NULL) return PS4RF_ERR_PROTOCOL;
    if (strcmp(error_name, "UnsafeNumber") == 0) return PS4RF_ERR_UNSAFE_NUMBER;
    if (strcmp(error_name, "TypeError") == 0) return PS4RF_ERR_TYPE;
    return PS4RF_ERR_PROTOCOL;
}

/* The canonicalization layer reports the reference's *exception name*; the
 * protocol layer surfaces it through the status enum. */
static ps4rf_status canonicalize_text(const char *text, size_t len, char **out, size_t *out_len)
{
    const char *err = NULL;
    if (ps4rf_canonical_bytes_text(text, len, out, out_len, &err) == 0) return PS4RF_OK;
    return ps4rf_status_from_error_name(err);
}

static ps4rf_status canonicalize_obj(const jval *v, char **out, size_t *out_len)
{
    const char *err = NULL;
    if (ps4rf_canonical_bytes(v, out, out_len, &err) == 0) return PS4RF_OK;
    return ps4rf_status_from_error_name(err);
}

/* ---------------------------------------------------------------------- hex */

void ps4rf_hex_encode(const uint8_t *data, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[2 * i] = digits[(data[i] >> 4) & 0x0f];
        out[2 * i + 1] = digits[data[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

ps4rf_status ps4rf_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t n, i;
    if (hex == NULL || out == NULL) return PS4RF_ERR_PROTOCOL;
    n = strlen(hex);
    if (n % 2 != 0 || n / 2 > out_cap) return PS4RF_ERR_PROTOCOL;
    for (i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return PS4RF_ERR_PROTOCOL;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    if (out_len != NULL) *out_len = n / 2;
    return PS4RF_OK;
}

/* ------------------------------------------------------------- handshake bits */

ps4rf_status ps4rf_transcript_hash(const char *hello_json, size_t hello_len,
                                   const char *ack_json, size_t ack_len, uint8_t out[32])
{
    char *hello_canon = NULL, *ack_canon = NULL;
    size_t hello_clen = 0, ack_clen = 0;
    uint8_t *buf = NULL;
    ps4rf_status st;

    st = canonicalize_text(hello_json, hello_len, &hello_canon, &hello_clen);
    if (st != PS4RF_OK) return st;
    st = canonicalize_text(ack_json, ack_len, &ack_canon, &ack_clen);
    if (st != PS4RF_OK) { free(hello_canon); return st; }

    buf = (uint8_t *)malloc(hello_clen + ack_clen);
    if (buf == NULL) { free(hello_canon); free(ack_canon); return PS4RF_ERR_PROTOCOL; }
    memcpy(buf, hello_canon, hello_clen);
    memcpy(buf + hello_clen, ack_canon, ack_clen);
    ps4rf_sha256(buf, hello_clen + ack_clen, out);
    free(buf);
    free(hello_canon);
    free(ack_canon);
    return PS4RF_OK;
}

static ps4rf_status hkdf_info(const char *prefix, const uint8_t transcript[32],
                              uint8_t *info_out, size_t *info_len_out)
{
    size_t prefix_len = strlen(prefix);
    memcpy(info_out, prefix, prefix_len);
    memcpy(info_out + prefix_len, transcript, 32);
    *info_len_out = prefix_len + 32;
    return PS4RF_OK;
}

ps4rf_status ps4rf_derive_keys(const uint8_t psk[32], const uint8_t agent_nonce[16],
                               const uint8_t host_nonce[16], const uint8_t transcript[32],
                               ps4rf_keys *out)
{
    uint8_t salt[32];
    uint8_t info[128];
    size_t info_len = 0;
    if (psk == NULL || agent_nonce == NULL || host_nonce == NULL || transcript == NULL ||
        out == NULL)
        return PS4RF_ERR_PROTOCOL;
    /* Python: derive_keys() rejects a secret/nonce length mismatch up front. */
    memcpy(salt, agent_nonce, 16);
    memcpy(salt + 16, host_nonce, 16);

    hkdf_info("ps4rf/handshake/v1", transcript, info, &info_len);
    if (ps4rf_hkdf_sha256(psk, 32, salt, 32, info, info_len, out->k_hs, 32) != 0)
        return PS4RF_ERR_PROTOCOL;
    hkdf_info("ps4rf/aead/agent-to-host/v1", transcript, info, &info_len);
    if (ps4rf_hkdf_sha256(psk, 32, salt, 32, info, info_len, out->k_agent_to_host, 32) != 0)
        return PS4RF_ERR_PROTOCOL;
    hkdf_info("ps4rf/aead/host-to-agent/v1", transcript, info, &info_len);
    if (ps4rf_hkdf_sha256(psk, 32, salt, 32, info, info_len, out->k_host_to_agent, 32) != 0)
        return PS4RF_ERR_PROTOCOL;
    return PS4RF_OK;
}

ps4rf_status ps4rf_nonce_prefix(const uint8_t psk[32], const uint8_t agent_nonce[16],
                                const uint8_t host_nonce[16], const uint8_t transcript[32],
                                ps4rf_direction dir, uint8_t out[4])
{
    char prefix_buf[96];
    uint8_t salt[32];
    uint8_t info[128];
    size_t info_len = 0;
    if (psk == NULL || agent_nonce == NULL || host_nonce == NULL || transcript == NULL ||
        out == NULL)
        return PS4RF_ERR_PROTOCOL;
    /* Frozen behaviour (F1 class): the info string carries the enum NAME form. */
    snprintf(prefix_buf, sizeof(prefix_buf), "ps4rf/nonce-prefix/%s/v1",
             ps4rf_direction_string(dir));
    memcpy(salt, agent_nonce, 16);
    memcpy(salt + 16, host_nonce, 16);
    hkdf_info(prefix_buf, transcript, info, &info_len);
    if (ps4rf_hkdf_sha256(psk, 32, salt, 32, info, info_len, out, 4) != 0)
        return PS4RF_ERR_PROTOCOL;
    return PS4RF_OK;
}

ps4rf_status ps4rf_proof(const uint8_t k_hs[32], const char *role, const uint8_t transcript[32],
                         uint8_t out[32])
{
    char prefix_buf[64];
    uint8_t msg[128];
    size_t prefix_len;
    if (k_hs == NULL || role == NULL || transcript == NULL || out == NULL)
        return PS4RF_ERR_PROTOCOL;
    snprintf(prefix_buf, sizeof(prefix_buf), "ps4rf/proof/%s/v1", role);
    prefix_len = strlen(prefix_buf);
    memcpy(msg, prefix_buf, prefix_len);
    memcpy(msg + prefix_len, transcript, 32);
    ps4rf_hmac_sha256(k_hs, 32, msg, prefix_len + 32, out);
    return PS4RF_OK;
}

ps4rf_status ps4rf_build_aad(uint32_t protocol_version, const char *session_id, uint64_t sequence,
                             ps4rf_direction dir, const char *message_type,
                             char **out, size_t *out_len)
{
    jval *obj = NULL;
    jval *value = NULL;
    char *canon = NULL;
    size_t canon_len = 0;
    ps4rf_status st;

    if (session_id == NULL || message_type == NULL || out == NULL || out_len == NULL)
        return PS4RF_ERR_PROTOCOL;

    obj = jval_new_object();
    if (obj == NULL) return PS4RF_ERR_PROTOCOL;

    value = jval_new_string(ps4rf_direction_string(dir));
    if (value == NULL || jval_obj_set(obj, "direction", value) != 0) goto oom;
    value = jval_new_string(message_type);
    if (value == NULL || jval_obj_set(obj, "message_type", value) != 0) goto oom;
    value = jval_new_int((int64_t)protocol_version);
    if (value == NULL || jval_obj_set(obj, "protocol_version", value) != 0) goto oom;
    value = jval_new_int((int64_t)sequence);
    if (value == NULL || jval_obj_set(obj, "sequence", value) != 0) goto oom;
    value = jval_new_string(session_id);
    if (value == NULL || jval_obj_set(obj, "session_id", value) != 0) goto oom;

    st = canonicalize_obj(obj, &canon, &canon_len);
    jval_free(obj);
    if (st != PS4RF_OK) return st;
    *out = canon;
    *out_len = canon_len;
    return PS4RF_OK;

oom:
    if (value != NULL) jval_free(value);
    jval_free(obj);
    return PS4RF_ERR_PROTOCOL;
}

/* ------------------------------------------------------------- AEAD channels */

ps4rf_status ps4rf_channel_init(ps4rf_channel *ch, const uint8_t key[32], const uint8_t prefix[4],
                                const char *session_id, ps4rf_direction dir, const char *suite,
                                size_t max_frame_bytes, uint32_t protocol_version)
{
    if (ch == NULL || key == NULL || prefix == NULL || session_id == NULL)
        return PS4RF_ERR_PROTOCOL;
    if (strlen(session_id) >= sizeof(ch->session_id)) return PS4RF_ERR_PROTOCOL;
    /* Only the suite the golden vectors exercise is implemented; the declared
     * alternative AES_256_GCM is out of the W2 scope and refused explicitly. */
    if (suite != NULL && strcmp(suite, "AEAD_CHACHA20_POLY1305") != 0)
        return PS4RF_ERR_PROTOCOL;
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->key, key, 32);
    memcpy(ch->prefix, prefix, 4);
    memcpy(ch->session_id, session_id, strlen(session_id) + 1);
    ch->dir = dir;
    ch->protocol_version = protocol_version;
    ch->max_frame_bytes = max_frame_bytes;
    ch->send_seq = 0;
    ch->recv_seq = 0;
    return PS4RF_OK;
}

static void nonce_for(const ps4rf_channel *ch, uint64_t seq, uint8_t nonce[12])
{
    int i;
    memcpy(nonce, ch->prefix, 4);
    for (i = 0; i < 8; i++)
        nonce[4 + i] = (uint8_t)((seq >> (8 * (7 - i))) & 0xffu);
}

ps4rf_status ps4rf_channel_seal(ps4rf_channel *ch, const char *message_type,
                                const uint8_t *pt, size_t pt_len,
                                uint64_t *seq_out, uint8_t *ct_out, size_t *ct_len_io)
{
    char *aad = NULL;
    size_t aad_len = 0;
    uint8_t nonce[12];
    uint64_t seq;
    size_t cap;
    ps4rf_status st;

    if (ch == NULL || message_type == NULL || ct_out == NULL || ct_len_io == NULL)
        return PS4RF_ERR_PROTOCOL;
    if (pt_len != 0 && pt == NULL) return PS4RF_ERR_PROTOCOL;
    /* Order matters (mirrors DirectionChannel.seal): frame limit first, so an
     * oversize frame leaves the sequence counter untouched. */
    if (pt_len + PS4RF_TAG_LEN > ch->max_frame_bytes) return PS4RF_ERR_FRAME_LIMIT;
    if (ch->send_seq > PS4RF_EFFECTIVE_LAST_SEQ) return PS4RF_ERR_SEQ_EXHAUSTED;
    seq = ch->send_seq;
    st = ps4rf_build_aad(ch->protocol_version, ch->session_id, seq, ch->dir, message_type,
                         &aad, &aad_len);
    if (st != PS4RF_OK) return st;
    nonce_for(ch, seq, nonce);
    cap = *ct_len_io;
    if (cap < pt_len + PS4RF_TAG_LEN) { free(aad); return PS4RF_ERR_PROTOCOL; }
    if (ps4rf_aead_seal(ch->key, nonce, aad, aad_len, pt, pt_len, ct_out, ct_len_io) != 0) {
        free(aad);
        return PS4RF_ERR_PROTOCOL;
    }
    free(aad);
    ch->send_seq = seq + 1;
    if (seq_out != NULL) *seq_out = seq;
    return PS4RF_OK;
}

ps4rf_status ps4rf_channel_open(ps4rf_channel *ch, const char *message_type, uint64_t sequence,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *pt_out, size_t *pt_len_io)
{
    char *aad = NULL;
    size_t aad_len = 0;
    uint8_t nonce[12];
    ps4rf_status st;

    if (ch == NULL || message_type == NULL || ct == NULL || pt_out == NULL || pt_len_io == NULL)
        return PS4RF_ERR_PROTOCOL;
    if (ch->recv_seq > PS4RF_EFFECTIVE_LAST_SEQ) return PS4RF_ERR_SEQ_EXHAUSTED;
    if (sequence != ch->recv_seq) return PS4RF_ERR_REPLAY;
    if (ct_len > ch->max_frame_bytes) return PS4RF_ERR_FRAME_LIMIT;
    /* A caller-provided buffer that cannot hold the plaintext is an argument
     * error, never an authentication failure. */
    if (ct_len < PS4RF_TAG_LEN || *pt_len_io < ct_len - PS4RF_TAG_LEN)
        return PS4RF_ERR_PROTOCOL;
    st = ps4rf_build_aad(ch->protocol_version, ch->session_id, sequence, ch->dir, message_type,
                         &aad, &aad_len);
    if (st != PS4RF_OK) return st;
    nonce_for(ch, sequence, nonce);
    if (ps4rf_aead_open(ch->key, nonce, aad, aad_len, ct, ct_len, pt_out, pt_len_io) != 0) {
        free(aad);
        return PS4RF_ERR_AUTH_FAILED; /* D9: the library failure never escapes */
    }
    free(aad);
    ch->recv_seq = sequence + 1;
    return PS4RF_OK;
}

/* ------------------------------------------------------- wire framing v1 (D12) */

const char *ps4rf_frame_type_name(uint8_t byte)
{
    switch (byte) {
    case 0x01: return "REQUEST";
    case 0x02: return "RESPONSE";
    case 0x03: return "EVENT";
    case 0x04: return "BYE";
    case 0x05: return "READY";
    default:   return NULL;
    }
}

int ps4rf_frame_type_byte(const char *message_type)
{
    if (message_type == NULL) return -1;
    if (strcmp(message_type, "REQUEST") == 0) return 0x01;
    if (strcmp(message_type, "RESPONSE") == 0) return 0x02;
    if (strcmp(message_type, "EVENT") == 0) return 0x03;
    if (strcmp(message_type, "BYE") == 0) return 0x04;
    if (strcmp(message_type, "READY") == 0) return 0x05;
    return -1;
}

int ps4rf_frame_type_is_reserved(const char *message_type)
{
    return message_type != NULL &&
           (strcmp(message_type, "EVENT") == 0 || strcmp(message_type, "READY") == 0);
}

ps4rf_status ps4rf_direction_check(ps4rf_direction dir, const char *message_type)
{
    if (message_type == NULL) return PS4RF_ERR_PROTOCOL;
    if (dir == PS4RF_DIR_AGENT_TO_HOST)
        return strcmp(message_type, "REQUEST") == 0 ? PS4RF_OK : PS4RF_ERR_PROTOCOL;
    return (strcmp(message_type, "RESPONSE") == 0 || strcmp(message_type, "EVENT") == 0 ||
            strcmp(message_type, "BYE") == 0)
               ? PS4RF_OK
               : PS4RF_ERR_PROTOCOL;
}

ps4rf_status ps4rf_frame_build_header(size_t ct_len, const char *message_type, uint64_t sequence,
                                      int allow_reserved, uint8_t out[PS4RF_FRAME_HEADER_BYTES])
{
    int type_byte;
    if (out == NULL || message_type == NULL) return PS4RF_ERR_PROTOCOL;
    if (sequence > PS4RF_EFFECTIVE_LAST_SEQ) return PS4RF_ERR_SEQ_EXHAUSTED;
    if (!allow_reserved && ps4rf_frame_type_is_reserved(message_type))
        return PS4RF_ERR_RESERVED_TYPE;
    type_byte = ps4rf_frame_type_byte(message_type);
    if (type_byte < 0) return PS4RF_ERR_UNKNOWN_TYPE;
    out[0] = (uint8_t)((ct_len >> 24) & 0xffu);
    out[1] = (uint8_t)((ct_len >> 16) & 0xffu);
    out[2] = (uint8_t)((ct_len >> 8) & 0xffu);
    out[3] = (uint8_t)(ct_len & 0xffu);
    out[4] = (uint8_t)type_byte;
    for (int i = 0; i < 8; i++) out[5 + i] = (uint8_t)((sequence >> (8 * (7 - i))) & 0xffu);
    return PS4RF_OK;
}

ps4rf_status ps4rf_frame_parse_header(const uint8_t raw[PS4RF_FRAME_HEADER_BYTES],
                                      size_t max_frame_bytes, char message_type_out[16],
                                      uint64_t *sequence_out, uint32_t *ct_len_out)
{
    const char *name;
    uint32_t length;
    uint64_t sequence;
    int i;
    if (raw == NULL || message_type_out == NULL || sequence_out == NULL || ct_len_out == NULL)
        return PS4RF_ERR_PROTOCOL;
    length = ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) | ((uint32_t)raw[2] << 8) |
             (uint32_t)raw[3];
    name = ps4rf_frame_type_name(raw[4]);
    if (name == NULL) return PS4RF_ERR_UNKNOWN_TYPE;
    sequence = 0;
    for (i = 0; i < 8; i++) sequence = (sequence << 8) | raw[5 + i];
    if (length > max_frame_bytes) return PS4RF_ERR_FRAME_LIMIT;
    if (sequence > PS4RF_EFFECTIVE_LAST_SEQ) return PS4RF_ERR_SEQ_EXHAUSTED;
    memcpy(message_type_out, name, strlen(name) + 1);
    *sequence_out = sequence;
    *ct_len_out = length;
    return PS4RF_OK;
}

ps4rf_status ps4rf_frame_encode(ps4rf_channel *ch, const char *message_type,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t **out, size_t *out_len, int allow_reserved)
{
    uint8_t header[PS4RF_FRAME_HEADER_BYTES];
    uint8_t *ct = NULL;
    size_t ct_len;
    uint64_t seq = 0;
    uint8_t *frame;
    ps4rf_status st;

    if (out == NULL || out_len == NULL) return PS4RF_ERR_PROTOCOL;
    if (pt_len > ch->max_frame_bytes) return PS4RF_ERR_FRAME_LIMIT;
    ct = (uint8_t *)malloc(pt_len + PS4RF_TAG_LEN);
    if (ct == NULL) return PS4RF_ERR_PROTOCOL;
    ct_len = pt_len + PS4RF_TAG_LEN;
    st = ps4rf_channel_seal(ch, message_type, pt, pt_len, &seq, ct, &ct_len);
    if (st != PS4RF_OK) { free(ct); return st; }
    st = ps4rf_frame_build_header(ct_len, message_type, seq, allow_reserved, header);
    if (st != PS4RF_OK) { free(ct); return st; }
    frame = (uint8_t *)malloc(PS4RF_FRAME_HEADER_BYTES + ct_len);
    if (frame == NULL) { free(ct); return PS4RF_ERR_PROTOCOL; }
    memcpy(frame, header, PS4RF_FRAME_HEADER_BYTES);
    memcpy(frame + PS4RF_FRAME_HEADER_BYTES, ct, ct_len);
    free(ct);
    *out = frame;
    *out_len = PS4RF_FRAME_HEADER_BYTES + ct_len;
    return PS4RF_OK;
}

ps4rf_status ps4rf_frame_decode(ps4rf_channel *ch, const uint8_t *frame, size_t frame_len,
                                char message_type_out[16], uint64_t *sequence_out,
                                uint8_t **pt_out, size_t *pt_len_out)
{
    char message_type[16];
    uint64_t sequence = 0;
    uint32_t ct_len = 0;
    const uint8_t *ct;
    uint8_t *pt;
    size_t pt_len;
    ps4rf_status st;

    if (ch == NULL || frame == NULL || pt_out == NULL || pt_len_out == NULL)
        return PS4RF_ERR_PROTOCOL;
    if (frame_len < PS4RF_FRAME_HEADER_BYTES) return PS4RF_ERR_PROTOCOL;
    st = ps4rf_frame_parse_header(frame, ch->max_frame_bytes, message_type, &sequence, &ct_len);
    if (st != PS4RF_OK) return st;
    if (frame_len - PS4RF_FRAME_HEADER_BYTES != ct_len) return PS4RF_ERR_PROTOCOL;
    ct = frame + PS4RF_FRAME_HEADER_BYTES;
    pt = (uint8_t *)malloc(ct_len == 0 ? 1 : ct_len);
    if (pt == NULL) return PS4RF_ERR_PROTOCOL;
    pt_len = ct_len;
    st = ps4rf_channel_open(ch, message_type, sequence, ct, ct_len, pt, &pt_len);
    if (st != PS4RF_OK) { free(pt); return st; }
    if (message_type_out != NULL) memcpy(message_type_out, message_type, strlen(message_type) + 1);
    if (sequence_out != NULL) *sequence_out = sequence;
    *pt_out = pt;
    *pt_len_out = pt_len;
    return PS4RF_OK;
}

/* ------------------------------------------------------ handshake transport I/O */

static int write_all(int fd, const uint8_t *buf, size_t len)
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

static int read_exact(int fd, uint8_t *buf, size_t len)
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

ps4rf_status ps4rf_hs_send(int fd, const jval *obj)
{
    char *canon = NULL;
    size_t canon_len = 0;
    uint8_t header[4];
    ps4rf_status st;

    st = canonicalize_obj(obj, &canon, &canon_len);
    if (st != PS4RF_OK) return st;
    if (canon_len > PS4RF_MAX_HANDSHAKE_BYTES) { free(canon); return PS4RF_ERR_LIMIT; }
    header[0] = (uint8_t)((canon_len >> 24) & 0xffu);
    header[1] = (uint8_t)((canon_len >> 16) & 0xffu);
    header[2] = (uint8_t)((canon_len >> 8) & 0xffu);
    header[3] = (uint8_t)(canon_len & 0xffu);
    if (write_all(fd, header, 4) != 0 || write_all(fd, (const uint8_t *)canon, canon_len) != 0) {
        free(canon);
        return PS4RF_ERR_PROTOCOL;
    }
    free(canon);
    return PS4RF_OK;
}

ps4rf_status ps4rf_hs_recv(int fd, jval **out)
{
    uint8_t header[4];
    size_t n;
    uint8_t *buf;
    jval *obj;

    if (out == NULL) return PS4RF_ERR_PROTOCOL;
    if (read_exact(fd, header, 4) != 0) return PS4RF_ERR_PROTOCOL;
    n = ((size_t)header[0] << 24) | ((size_t)header[1] << 16) | ((size_t)header[2] << 8) |
        (size_t)header[3];
    if (n > PS4RF_MAX_HANDSHAKE_BYTES) return PS4RF_ERR_LIMIT;
    buf = (uint8_t *)malloc(n + 1);
    if (buf == NULL) return PS4RF_ERR_PROTOCOL;
    if (read_exact(fd, buf, n) != 0) { free(buf); return PS4RF_ERR_PROTOCOL; }
    buf[n] = '\0';
    obj = jval_parse((const char *)buf, n);
    free(buf);
    if (obj == NULL) return PS4RF_ERR_PARSE;
    *out = obj;
    return PS4RF_OK;
}

/* Reads a hex-encoded 16-byte nonce, as the reference does with bytes.fromhex(). */
static ps4rf_status nonce_from_obj(const jval *obj, const char *key, uint8_t out[16])
{
    const jval *field;
    const char *text;
    size_t len = 0;
    if (obj == NULL) return PS4RF_ERR_PROTOCOL;
    field = jval_get(obj, key);
    if (field == NULL || jval_kind(field) != JVAL_STRING) return PS4RF_ERR_PROTOCOL;
    text = jval_string(field, &len);
    if (text == NULL || len != 32) return PS4RF_ERR_PROTOCOL;
    return ps4rf_hex_decode(text, out, 16, NULL);
}

static ps4rf_status mac_matches(const jval *obj, const uint8_t expected[32])
{
    const jval *mac;
    char expected_hex[65];
    size_t len = 0;
    const char *text;
    if (obj == NULL) return PS4RF_ERR_PROTOCOL;
    mac = jval_get(obj, "mac");
    if (mac == NULL || jval_kind(mac) != JVAL_STRING) return PS4RF_ERR_PROTOCOL;
    text = jval_string(mac, &len);
    ps4rf_hex_encode(expected, 32, expected_hex);
    if (text == NULL || strcmp(text, expected_hex) != 0) return PS4RF_ERR_PROTOCOL;
    return PS4RF_OK;
}

ps4rf_status ps4rf_agent_handshake(int fd, const uint8_t psk[32], const jval *agent_hello,
                                   ps4rf_keys *keys, jval **ack_out)
{
    jval *ack = NULL;
    uint8_t transcript[32];
    uint8_t agent_nonce[16], host_nonce[16];
    uint8_t mac[32];
    jval *auth = NULL;
    jval *auth_ack = NULL;
    char mac_hex[65];
    ps4rf_status st;

    if (agent_hello == NULL) return PS4RF_ERR_PROTOCOL;
    st = ps4rf_hs_send(fd, agent_hello);
    if (st != PS4RF_OK) return st;
    st = ps4rf_hs_recv(fd, &ack);
    if (st != PS4RF_OK) return st;
    st = nonce_from_obj(agent_hello, "nonce", agent_nonce);
    if (st == PS4RF_OK) st = nonce_from_obj(ack, "nonce", host_nonce);
    if (st == PS4RF_OK) {
        char *hello_canon = NULL, *ack_canon = NULL;
        size_t hello_len = 0, ack_len = 0;
        st = canonicalize_obj(agent_hello, &hello_canon, &hello_len);
        if (st == PS4RF_OK) {
            st = canonicalize_obj(ack, &ack_canon, &ack_len);
            if (st == PS4RF_OK) {
                uint8_t *buf = (uint8_t *)malloc(hello_len + ack_len);
                if (buf == NULL) st = PS4RF_ERR_PROTOCOL;
                else {
                    memcpy(buf, hello_canon, hello_len);
                    memcpy(buf + hello_len, ack_canon, ack_len);
                    ps4rf_sha256(buf, hello_len + ack_len, transcript);
                    free(buf);
                }
            }
            free(hello_canon);
            if (ack_canon != NULL) free(ack_canon);
        }
    }
    if (st != PS4RF_OK) { jval_free(ack); return st; }
    if (keys != NULL) {
        st = ps4rf_derive_keys(psk, agent_nonce, host_nonce, transcript, keys);
        if (st != PS4RF_OK) { jval_free(ack); return st; }
    }
    {
        ps4rf_keys local_keys;
        const uint8_t *k_hs = NULL;
        if (keys != NULL) k_hs = keys->k_hs;
        else {
            st = ps4rf_derive_keys(psk, agent_nonce, host_nonce, transcript, &local_keys);
            if (st != PS4RF_OK) { jval_free(ack); return st; }
            k_hs = local_keys.k_hs;
        }
        st = ps4rf_proof(k_hs, "agent", transcript, mac);
        if (st != PS4RF_OK) { jval_free(ack); return st; }
    }
    ps4rf_hex_encode(mac, 32, mac_hex);
    auth = jval_new_object();
    if (auth == NULL ||
        jval_obj_set(auth, "mac", jval_new_string(mac_hex)) != 0 ||
        jval_obj_set(auth, "msg", jval_new_string("AUTH")) != 0) {
        jval_free(auth);
        jval_free(ack);
        return PS4RF_ERR_PROTOCOL;
    }
    st = ps4rf_hs_send(fd, auth);
    jval_free(auth);
    if (st != PS4RF_OK) { jval_free(ack); return st; }
    st = ps4rf_hs_recv(fd, &auth_ack);
    if (st != PS4RF_OK) { jval_free(ack); return st; }
    {
        ps4rf_keys local_keys;
        const uint8_t *k_hs = NULL;
        uint8_t host_mac[32];
        if (keys != NULL) k_hs = keys->k_hs;
        else {
            st = ps4rf_derive_keys(psk, agent_nonce, host_nonce, transcript, &local_keys);
            if (st != PS4RF_OK) { jval_free(auth_ack); jval_free(ack); return st; }
            k_hs = local_keys.k_hs;
        }
        st = ps4rf_proof(k_hs, "host", transcript, host_mac);
        if (st == PS4RF_OK) st = mac_matches(auth_ack, host_mac);
    }
    jval_free(auth_ack);
    if (st != PS4RF_OK) { jval_free(ack); return PS4RF_ERR_PROTOCOL; }
    if (ack_out != NULL) { *ack_out = ack; }
    else jval_free(ack);
    return PS4RF_OK;
}

ps4rf_status ps4rf_host_handshake(int fd, const uint8_t psk[32], const jval *host_hello_ack,
                                  ps4rf_keys *keys, jval **hello_out)
{
    jval *hello = NULL;
    uint8_t transcript[32];
    uint8_t agent_nonce[16], host_nonce[16];
    uint8_t mac[32];
    jval *auth = NULL;
    jval *auth_ack = NULL;
    char mac_hex[65];
    ps4rf_status st;

    if (host_hello_ack == NULL) return PS4RF_ERR_PROTOCOL;
    st = ps4rf_hs_recv(fd, &hello);
    if (st != PS4RF_OK) return st;
    st = ps4rf_hs_send(fd, host_hello_ack);
    if (st != PS4RF_OK) { jval_free(hello); return st; }
    st = nonce_from_obj(hello, "nonce", agent_nonce);
    if (st == PS4RF_OK) st = nonce_from_obj(host_hello_ack, "nonce", host_nonce);
    if (st == PS4RF_OK) {
        char *hello_canon = NULL, *ack_canon = NULL;
        size_t hello_len = 0, ack_len = 0;
        st = canonicalize_obj(hello, &hello_canon, &hello_len);
        if (st == PS4RF_OK) {
            st = canonicalize_obj(host_hello_ack, &ack_canon, &ack_len);
            if (st == PS4RF_OK) {
                uint8_t *buf = (uint8_t *)malloc(hello_len + ack_len);
                if (buf == NULL) st = PS4RF_ERR_PROTOCOL;
                else {
                    memcpy(buf, hello_canon, hello_len);
                    memcpy(buf + hello_len, ack_canon, ack_len);
                    ps4rf_sha256(buf, hello_len + ack_len, transcript);
                    free(buf);
                }
            }
            free(hello_canon);
            if (ack_canon != NULL) free(ack_canon);
        }
    }
    if (st != PS4RF_OK) { jval_free(hello); return st; }
    if (keys != NULL) {
        st = ps4rf_derive_keys(psk, agent_nonce, host_nonce, transcript, keys);
        if (st != PS4RF_OK) { jval_free(hello); return st; }
    }
    {
        ps4rf_keys local_keys;
        const uint8_t *k_hs = NULL;
        uint8_t agent_mac[32];
        if (keys != NULL) k_hs = keys->k_hs;
        else {
            st = ps4rf_derive_keys(psk, agent_nonce, host_nonce, transcript, &local_keys);
            if (st != PS4RF_OK) { jval_free(hello); return st; }
            k_hs = local_keys.k_hs;
        }
        st = ps4rf_hs_recv(fd, &auth);
        if (st != PS4RF_OK) { jval_free(hello); return st; }
        st = ps4rf_proof(k_hs, "agent", transcript, agent_mac);
        if (st == PS4RF_OK) st = mac_matches(auth, agent_mac);
        jval_free(auth);
        if (st != PS4RF_OK) { jval_free(hello); return PS4RF_ERR_PROTOCOL; }
        st = ps4rf_proof(k_hs, "host", transcript, mac);
        if (st != PS4RF_OK) { jval_free(hello); return st; }
    }
    ps4rf_hex_encode(mac, 32, mac_hex);
    auth_ack = jval_new_object();
    if (auth_ack == NULL ||
        jval_obj_set(auth_ack, "mac", jval_new_string(mac_hex)) != 0 ||
        jval_obj_set(auth_ack, "msg", jval_new_string("AUTH_ACK")) != 0) {
        jval_free(auth_ack);
        jval_free(hello);
        return PS4RF_ERR_PROTOCOL;
    }
    st = ps4rf_hs_send(fd, auth_ack);
    jval_free(auth_ack);
    if (st != PS4RF_OK) { jval_free(hello); return st; }
    if (hello_out != NULL) { *hello_out = hello; }
    else jval_free(hello);
    return PS4RF_OK;
}
