/* PS4RF native protocol core -- userland skeleton, wire spec v1 (P4/W2).
 *
 * This is the native (C) counterpart of the frozen Python reference in
 * core/rpc/handshake.py, core/rpc/wire.py and core/canonical.py. Every function
 * here must reproduce those bytes exactly; the parity harness proves it against
 * the two golden catalogs.
 *
 * Scope note (W2): userland only, no console interaction, no research
 * primitives. The request loop handles the two skeleton operations only.
 *
 * Error naming: ps4rf_status_name() returns the *Python* exception name
 * ("ProtocolError", "ReplayDetected", ...) so the harness can compare outcomes
 * by name, exactly like the catalogs record them.
 */
#ifndef PS4RF_PROTOCOL_H
#define PS4RF_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "jcs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PS4RF_HANDSHAKE_LABEL "ps4rf-handshake-v1"
#define PS4RF_MAX_HANDSHAKE_BYTES 65536u
#define PS4RF_TAG_LEN 16u
#define PS4RF_FRAME_HEADER_BYTES 13u
#define PS4RF_MAX_FRAME_BYTES_DEFAULT 1048576u

/* 2**64 - 2: representable space of the 8-byte header field (documentation only). */
#define PS4RF_LAST_SEQ 18446744073709551614ULL
/* W0/D8: the AAD carries the sequence as a JCS integer, so this is the usable ceiling. */
#define PS4RF_EFFECTIVE_LAST_SEQ 9007199254740991ULL /* 2**53 - 1 */

typedef enum {
    PS4RF_OK = 0,
    PS4RF_ERR_PROTOCOL = 1,      /* ProtocolError          */
    PS4RF_ERR_REPLAY = 2,        /* ReplayDetected         */
    PS4RF_ERR_SEQ_EXHAUSTED = 3, /* SequenceExhausted      */
    PS4RF_ERR_FRAME_LIMIT = 4,   /* FrameLimitExceeded     */
    PS4RF_ERR_AUTH_FAILED = 5,   /* AuthenticationFailed   */
    PS4RF_ERR_UNKNOWN_TYPE = 6,  /* UnknownFrameType       */
    PS4RF_ERR_RESERVED_TYPE = 7, /* ReservedFrameType      */
    PS4RF_ERR_UNSAFE_NUMBER = 8, /* UnsafeNumber           */
    PS4RF_ERR_TYPE = 9,          /* TypeError              */
    PS4RF_ERR_PARSE = 10,        /* JSON syntax error      */
    PS4RF_ERR_LIMIT = 11         /* handshake frame too large */
} ps4rf_status;

/* Python exception name for a status, or NULL for PS4RF_OK ("" for unknown). */
const char *ps4rf_status_name(ps4rf_status status);

/* Maps the canonicalization layer's error name ("UnsafeNumber", "TypeError")
 * onto the protocol status enum; NULL/unknown becomes ProtocolError. */
ps4rf_status ps4rf_status_from_error_name(const char *error_name);

typedef enum { PS4RF_DIR_AGENT_TO_HOST = 0, PS4RF_DIR_HOST_TO_AGENT = 1 } ps4rf_direction;

/* "Direction.AGENT_TO_HOST" / "Direction.HOST_TO_AGENT" -- the frozen F1 form
 * (str(direction) of a (str, Enum)); also used inside nonce-prefix info strings. */
const char *ps4rf_direction_string(ps4rf_direction dir);

/* ------------------------------------------------------------------ handshake */

typedef struct {
    uint8_t k_hs[32];
    uint8_t k_agent_to_host[32];
    uint8_t k_host_to_agent[32];
} ps4rf_keys;

/* sha256(canonical(hello) || canonical(ack)) -- canonicalization uses the
 * protocol policy layer (safe numbers, sorted keys, no whitespace). */
ps4rf_status ps4rf_transcript_hash(const char *hello_json, size_t hello_len,
                                   const char *ack_json, size_t ack_len, uint8_t out[32]);

/* HKDF-SHA256 from the 32-byte PSK, salt = agent_nonce || host_nonce (16+16),
 * transcript TH; produces k_hs, k_agent_to_host, k_host_to_agent. */
ps4rf_status ps4rf_derive_keys(const uint8_t psk[32], const uint8_t agent_nonce[16],
                               const uint8_t host_nonce[16], const uint8_t transcript[32],
                               ps4rf_keys *out);

/* 4-byte nonce prefix, info = "ps4rf/nonce-prefix/" + Direction.NAME + "/v1" + TH. */
ps4rf_status ps4rf_nonce_prefix(const uint8_t psk[32], const uint8_t agent_nonce[16],
                                const uint8_t host_nonce[16], const uint8_t transcript[32],
                                ps4rf_direction dir, uint8_t out[4]);

/* HMAC-SHA256(k_hs, "ps4rf/proof/" + role + "/v1" + TH); role is "agent" or "host". */
ps4rf_status ps4rf_proof(const uint8_t k_hs[32], const char *role, const uint8_t transcript[32],
                         uint8_t out[32]);

/* Lowercase hex encoding into a caller buffer (needs 2*len+1 bytes). */
void ps4rf_hex_encode(const uint8_t *data, size_t len, char *out);
/* Strict hex decoding; returns PS4RF_OK only for an even, all-hex string. */
ps4rf_status ps4rf_hex_decode(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len);

/* AAD bytes: canonical JCS of {"direction","message_type","protocol_version",
 * "sequence","session_id"} with the frozen direction string. Caller frees *out. */
ps4rf_status ps4rf_build_aad(uint32_t protocol_version, const char *session_id, uint64_t sequence,
                             ps4rf_direction dir, const char *message_type,
                             char **out, size_t *out_len);

/* ------------------------------------------------------------- AEAD channels */

typedef struct {
    uint8_t key[32];
    uint8_t prefix[4];
    char session_id[64];
    ps4rf_direction dir;
    uint32_t protocol_version;
    size_t max_frame_bytes;
    uint64_t send_seq;
    uint64_t recv_seq;
} ps4rf_channel;

/* suite is the wire name; NULL means "AEAD_CHACHA20_POLY1305". Any other suite
 * (including the declared-but-unimplemented "AES_256_GCM") -> PS4RF_ERR_PROTOCOL. */
ps4rf_status ps4rf_channel_init(ps4rf_channel *ch, const uint8_t key[32], const uint8_t prefix[4],
                                const char *session_id, ps4rf_direction dir, const char *suite,
                                size_t max_frame_bytes, uint32_t protocol_version);

/* Mirrors DirectionChannel.seal: frame-limit check first (an oversize frame must
 * NOT consume a sequence), then the effective-ceiling check, then AEAD. Writes
 * ciphertext||tag into ct_out. */
ps4rf_status ps4rf_channel_seal(ps4rf_channel *ch, const char *message_type,
                                const uint8_t *pt, size_t pt_len,
                                uint64_t *seq_out, uint8_t *ct_out, size_t *ct_len_io);

/* Mirrors DirectionChannel.open: ceiling -> replay/sequence -> frame limit ->
 * AEAD (authentication failures become PS4RF_ERR_AUTH_FAILED, never a library
 * error). *pt_len_io must carry the capacity of pt_out on entry (the ciphertext
 * includes the 16-byte tag); a too-small buffer is refused before the AEAD call. */
ps4rf_status ps4rf_channel_open(ps4rf_channel *ch, const char *message_type, uint64_t sequence,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *pt_out, size_t *pt_len_io);

/* ------------------------------------------------------- wire framing v1 (D12) */

/* Mapping v1, single source: 0x01 REQUEST, 0x02 RESPONSE, 0x03 EVENT (reserved),
 * 0x04 BYE, 0x05 READY (reserved). */
const char *ps4rf_frame_type_name(uint8_t byte);            /* NULL when unknown */
int ps4rf_frame_type_byte(const char *message_type);        /* -1 unknown */
int ps4rf_frame_type_is_reserved(const char *message_type); /* 1 for EVENT/READY */

/* F16 direction rule: agent receives REQUEST only; host receives RESPONSE/EVENT/BYE. */
ps4rf_status ps4rf_direction_check(ps4rf_direction dir, const char *message_type);

ps4rf_status ps4rf_frame_build_header(size_t ct_len, const char *message_type, uint64_t sequence,
                                      int allow_reserved, uint8_t out[PS4RF_FRAME_HEADER_BYTES]);
ps4rf_status ps4rf_frame_parse_header(const uint8_t raw[PS4RF_FRAME_HEADER_BYTES],
                                      size_t max_frame_bytes, char message_type_out[16],
                                      uint64_t *sequence_out, uint32_t *ct_len_out);

/* header + sealed frame; refuses reserved types unless allow_reserved. Caller frees *out. */
ps4rf_status ps4rf_frame_encode(ps4rf_channel *ch, const char *message_type,
                                const uint8_t *pt, size_t pt_len,
                                uint8_t **out, size_t *out_len, int allow_reserved);
/* validates header, then opens; caller frees *pt_out. */
ps4rf_status ps4rf_frame_decode(ps4rf_channel *ch, const uint8_t *frame, size_t frame_len,
                                char message_type_out[16], uint64_t *sequence_out,
                                uint8_t **pt_out, size_t *pt_len_out);

/* ------------------------------------------------------ handshake transport I/O */

/* 4-byte big-endian length prefix + canonical bytes; refuses > MAX_HANDSHAKE_BYTES
 * before touching the socket. The object is not consumed. */
ps4rf_status ps4rf_hs_send(int fd, const jval *obj);
/* reads one length-prefixed canonical JSON object; caller frees *out. */
ps4rf_status ps4rf_hs_recv(int fd, jval **out);

/* Full agent side: HELLO -> HELLO_ACK -> AUTH -> AUTH_ACK (host proof verified).
 * keys/ack_out are optional (ack_out receives a copy the caller frees). */
ps4rf_status ps4rf_agent_handshake(int fd, const uint8_t psk[32], const jval *agent_hello,
                                   ps4rf_keys *keys, jval **ack_out);
/* Full host side (offline loopback/self-test): _recv HELLO -> send ACK -> verify
 * agent proof -> send AUTH_ACK. */
ps4rf_status ps4rf_host_handshake(int fd, const uint8_t psk[32], const jval *host_hello_ack,
                                  ps4rf_keys *keys, jval **hello_out);

#ifdef __cplusplus
}
#endif
#endif /* PS4RF_PROTOCOL_H */
