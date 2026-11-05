/*
 * test_sha256.c -- PS4RF native crypto self-test (W2 acceptance).
 *
 * Proves byte parity of the self-contained C99 implementation in
 * native/src/sha256.c (SHA-256 / HMAC-SHA256 / HKDF-SHA256) against the
 * frozen golden-vector catalog tests/fixtures/crypto/vectors-v1.json
 * (sha256 452ecc195f49329325e3ba0557ce1327e10d8e4f71b9e3e06a36a8c6721edd8b). The catalog values below were extracted with the
 * system python3 (stdlib only) and embedded as hex string literals.
 *
 * Covered:
 *   [1] rfc_vectors.rfc4231_hmac_sha256 -- all 6 catalog cases, full
 *       32-byte MAC compared (RFC 4231 case 5 is withdrawn because its
 *       MAC is truncated).
 *   [2] rfc_vectors.rfc5869_hkdf_sha256 -- all 3 cases; the intermediate
 *       PRK (= HMAC-SHA256(salt, IKM), HKDF-Extract) and the final OKM of
 *       length L are each compared.
 *   [3] protocol.* -- handshake v1 values: transcript_sha256 =
 *       SHA256(canon(hello) || canon(ack)) over the hex-decoded canonical
 *       byte strings; k_hs / k_agent_to_host / k_host_to_agent via
 *       HKDF-SHA256(ikm = psk, salt = agent_nonce || host_nonce,
 *       info = label || transcript-bytes, out_len 32); the two 4-byte
 *       nonce prefixes (enum-NAME info spelling, frozen behaviour);
 *       auth_mac / auth_ack_mac = HMAC-SHA256(k_hs,
 *       'ps4rf/proof/agent/v1' or 'ps4rf/proof/host/v1', then the raw
 *       32 transcript bytes).
 *   [4] Well-known SHA-256 digests of "abc" and of the empty string.
 *   [5] ps4rf_hkdf_sha256 argument-validation contract (-1 cases) and the
 *       legal all-empty extract/expand call.
 *
 * Prints one PASS/FAIL line per check; exit status is 0 only when every
 * check passed.
 *
 * Build (from the repository root):
 *   gcc -std=c99 -O2 -Wall -Wextra -Werror -o /tmp/test_sha256 \
 *       native/tests/test_sha256.c native/src/sha256.c
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/sha256.h"

/* ==== BEGIN EMBEDDED GOLDEN VECTORS ==== */
/* Extracted from tests/fixtures/crypto/vectors-v1.json
 * (sha256 452ecc195f49329325e3ba0557ce1327e10d8e4f71b9e3e06a36a8c6721edd8b)
 * with the system python3, stdlib only; do not edit by hand. */
struct rfc4231_case { const char *id; const char *key_hex; const char *data_hex; const char *mac_hex; };
static const struct rfc4231_case RFC4231_CASES[] = {
    { "1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
    { "2", "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
    { "3", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
    { "4", "0102030405060708090a0b0c0d0e0f10111213141516171819", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" },
    { "6", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
    { "7", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" },
};

struct rfc5869_case { const char *id; const char *ikm_hex; const char *salt_hex;
                      const char *info_hex; const char *prk_hex; const char *okm_hex;
                      unsigned out_len; };
static const struct rfc5869_case RFC5869_CASES[] = {
    { "1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42u },
    { "2", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87", 82u },
    { "3", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42u },
};

static const char PROTO_HELLO_CANONICAL_HEX[] =
    "7b226167656e745f76657273696f6e223a22766563746f722d302e312e30222c22636f6e74657874223a22766563746f722d636f6e74657874222c226c6162656c223a2270733472662d68616e647368616b652d7631222c226d7367223a2248454c4c4f222c226e6f6e6365223a223030303130323033303430353036303730383039306130623063306430653066222c2270726f7669646572223a22766563746f722d70726f7669646572222c227265636f766572795f7265717569726564223a66616c73652c227472616e73706f7274223a22766563746f722d7472616e73706f7274227d";  /* protocol.exchange.hello_canonical_hex */
static const char PROTO_HELLO_ACK_CANONICAL_HEX[] =
    "7b2261656164223a22414541445f43484143484132305f504f4c5931333035222c22617574685f7265717569726564223a747275652c226c696d697473223a7b226d61785f6368756e6b5f6279746573223a313034383537362c226d61785f69725f6279746573223a3236323134347d2c226d7367223a2248454c4c4f5f41434b222c226e6f6e6365223a223130313131323133313431353136313731383139316131623163316431653166222c2270726f746f636f6c5f76657273696f6e223a312c2273657373696f6e5f6964223a225345532d30313233343536373839414243444546227d";  /* protocol.exchange.hello_ack_canonical_hex */
static const char PROTO_TRANSCRIPT_SHA256_HEX[] =
    "67100a45ce21f2300b89b38a756504620261af59adcd9d6c2444019c60a74ad3";  /* protocol.transcript_sha256 */
static const char PROTO_PSK_HEX[] =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";  /* protocol.test_only_material.psk_hex */
static const char PROTO_AGENT_NONCE_HEX[] =
    "000102030405060708090a0b0c0d0e0f";  /* protocol.test_only_material.agent_nonce_hex */
static const char PROTO_HOST_NONCE_HEX[] =
    "101112131415161718191a1b1c1d1e1f";  /* protocol.test_only_material.host_nonce_hex */
static const char PROTO_K_HS_HEX[] =
    "03c57c1fb7df0a5830f47d5559377c6fc6427c770d6cb1e1ade59388ca3c4196";  /* protocol.keys.k_hs */
static const char PROTO_K_A2H_HEX[] =
    "8a6d948229b65edf2fc138805a87a18c136fbe126102cd0bfccf3d446b155d97";  /* protocol.keys.k_agent_to_host */
static const char PROTO_K_H2A_HEX[] =
    "10eca20a4a0ffa654d3c2500ffcbf380d6941987cf8e889771761bcdeee6a1a5";  /* protocol.keys.k_host_to_agent */
static const char PROTO_PREFIX_A2H_HEX[] =
    "6470db33";  /* protocol.nonce_prefixes.agent_to_host */
static const char PROTO_PREFIX_H2A_HEX[] =
    "7cf6b6e3";  /* protocol.nonce_prefixes.host_to_agent */
static const char PROTO_AUTH_MAC_HEX[] =
    "615de5671c86df7915d1831ae69ab00dd0332826807f55d595b4394c86f27541";  /* protocol.exchange.auth_mac_hex */
static const char PROTO_AUTH_ACK_MAC_HEX[] =
    "3b41f78e6e4e6b870ac99112685c11a3e83d8f4a78006895ed859ff9814caf85";  /* protocol.exchange.auth_ack_mac_hex */
/* ==== END EMBEDDED GOLDEN VECTORS ==== */

struct key_case { const char *id; const char *label; const char *want_hex; };
struct np_case  { const char *id; const char *label; const char *want_hex; };

/* Protocol info strings; the two nonce-prefix labels use the enum-NAME
 * spelling on purpose (frozen v1 behaviour, see core/rpc/handshake.py). */
static const struct key_case KEY_CASES[] = {
    { "protocol.keys.k_hs", "ps4rf/handshake/v1", PROTO_K_HS_HEX },
    { "protocol.keys.k_agent_to_host", "ps4rf/aead/agent-to-host/v1", PROTO_K_A2H_HEX },
    { "protocol.keys.k_host_to_agent", "ps4rf/aead/host-to-agent/v1", PROTO_K_H2A_HEX }
};

static const struct np_case NP_CASES[] = {
    { "protocol.nonce_prefixes.agent_to_host",
      "ps4rf/nonce-prefix/Direction.AGENT_TO_HOST/v1", PROTO_PREFIX_A2H_HEX },
    { "protocol.nonce_prefixes.host_to_agent",
      "ps4rf/nonce-prefix/Direction.HOST_TO_AGENT/v1", PROTO_PREFIX_H2A_HEX }
};

static const char PROOF_LABEL_AGENT[] = "ps4rf/proof/agent/v1";
static const char PROOF_LABEL_HOST[]  = "ps4rf/proof/host/v1";

static size_t g_checks = 0;
static size_t g_failures = 0;

static int hex_nibble(unsigned char c)
{
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9') return (int)c - (int)'0';
    if (c >= (unsigned char)'a' && c <= (unsigned char)'f') return (int)c - (int)'a' + 10;
    if (c >= (unsigned char)'A' && c <= (unsigned char)'F') return (int)c - (int)'A' + 10;
    return -1;
}

/* Decode a hex string into out; returns the byte count or (size_t)-1. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex);
    size_t i;

    if ((n % 2u) != 0u || n / 2u > cap) return (size_t)-1;
    for (i = 0; i < n / 2u; i++) {
        int hi = hex_nibble((unsigned char)hex[2u * i]);
        int lo = hex_nibble((unsigned char)hex[2u * i + 1u]);
        if (hi < 0 || lo < 0) return (size_t)-1;
        out[i] = (uint8_t)(((unsigned)hi << 4) | (unsigned)lo);
    }
    return n / 2u;
}

static void check_bytes(const char *id, const uint8_t *got, const uint8_t *want, size_t len)
{
    size_t i;

    g_checks++;
    if (memcmp(got, want, len) == 0) {
        printf("PASS  %s\n", id);
        return;
    }
    g_failures++;
    printf("FAIL  %s\n", id);
    printf("        got  ");
    for (i = 0; i < len; i++) printf("%02x", (unsigned)got[i]);
    printf("\n        want ");
    for (i = 0; i < len; i++) printf("%02x", (unsigned)want[i]);
    printf("\n");
}

static void fail_id(const char *id, const char *why)
{
    g_checks++;
    g_failures++;
    printf("FAIL  %s (%s)\n", id, why);
}

static void expect_true(const char *id, int cond)
{
    g_checks++;
    if (cond) {
        printf("PASS  %s\n", id);
    } else {
        g_failures++;
        printf("FAIL  %s\n", id);
    }
}

int main(void)
{
    size_t i;

    /* ---------- [1] RFC 4231 HMAC-SHA256 (6 catalog cases) ---------- */
    for (i = 0; i < sizeof(RFC4231_CASES) / sizeof(RFC4231_CASES[0]); i++) {
        const struct rfc4231_case *tc = &RFC4231_CASES[i];
        uint8_t key[256], data[512], want[32], got[32];
        size_t key_len, data_len, want_len;
        char id[128];

        key_len = unhex(tc->key_hex, key, sizeof(key));
        data_len = unhex(tc->data_hex, data, sizeof(data));
        want_len = unhex(tc->mac_hex, want, sizeof(want));
        snprintf(id, sizeof(id), "[1] RFC 4231 case %s HMAC-SHA256", tc->id);
        if (key_len == (size_t)-1 || data_len == (size_t)-1 || want_len != 32u) {
            fail_id(id, "embedded vector decode");
            continue;
        }
        ps4rf_hmac_sha256(key, key_len, data, data_len, got);
        check_bytes(id, got, want, 32u);
    }

    /* ---------- [2] RFC 5869 HKDF-SHA256 (3 catalog cases) ---------- */
    for (i = 0; i < sizeof(RFC5869_CASES) / sizeof(RFC5869_CASES[0]); i++) {
        const struct rfc5869_case *tc = &RFC5869_CASES[i];
        uint8_t ikm[128], salt[128], info[128];
        uint8_t prk_got[32], prk_want[32];
        uint8_t okm_got[128], okm_want[128];
        size_t ikm_len, salt_len, info_len, okm_len, prk_want_len;
        char id[128];
        int rc;

        ikm_len = unhex(tc->ikm_hex, ikm, sizeof(ikm));
        salt_len = unhex(tc->salt_hex, salt, sizeof(salt));
        info_len = unhex(tc->info_hex, info, sizeof(info));
        prk_want_len = unhex(tc->prk_hex, prk_want, sizeof(prk_want));
        okm_len = unhex(tc->okm_hex, okm_want, sizeof(okm_want));
        snprintf(id, sizeof(id), "[2] RFC 5869 case %s", tc->id);
        if (ikm_len == (size_t)-1 || salt_len == (size_t)-1 || info_len == (size_t)-1 ||
            prk_want_len != 32u || okm_len != (size_t)tc->out_len) {
            fail_id(id, "embedded vector decode");
            continue;
        }

        /* Extract: PRK = HMAC-SHA256(salt, IKM) (RFC 5869 section 2.2). */
        ps4rf_hmac_sha256(salt, salt_len, ikm, ikm_len, prk_got);
        snprintf(id, sizeof(id), "[2] RFC 5869 case %s PRK (extract)", tc->id);
        check_bytes(id, prk_got, prk_want, 32u);

        /* Expand: OKM = HKDF-Expand(PRK, info, L) (RFC 5869 section 2.3). */
        memset(okm_got, 0, sizeof(okm_got));
        rc = ps4rf_hkdf_sha256(ikm, ikm_len, salt, salt_len, info, info_len, okm_got, okm_len);
        snprintf(id, sizeof(id), "[2] RFC 5869 case %s OKM (L=%u)", tc->id, tc->out_len);
        if (rc != 0) {
            fail_id(id, "hkdf returned non-zero");
            continue;
        }
        check_bytes(id, okm_got, okm_want, okm_len);
    }

    /* ---------- [3] PS4RF protocol handshake v1 values ---------- */
    {
        uint8_t hello[2048], ack[2048], concat[4096];
        uint8_t th[32], th_want[32];
        uint8_t psk[64], an[32], hn[32], salt[64];
        uint8_t k_hs[32], out[64], want[64];
        uint8_t info[160], msg[128], mac[32];
        size_t hello_len, ack_len, th_want_len;
        size_t psk_len, an_len, hn_len, salt_len, want_len, label_len, kc;
        int ok = 1;

        hello_len = unhex(PROTO_HELLO_CANONICAL_HEX, hello, sizeof(hello));
        ack_len = unhex(PROTO_HELLO_ACK_CANONICAL_HEX, ack, sizeof(ack));
        th_want_len = unhex(PROTO_TRANSCRIPT_SHA256_HEX, th_want, sizeof(th_want));
        psk_len = unhex(PROTO_PSK_HEX, psk, sizeof(psk));
        an_len = unhex(PROTO_AGENT_NONCE_HEX, an, sizeof(an));
        hn_len = unhex(PROTO_HOST_NONCE_HEX, hn, sizeof(hn));

        if (hello_len == (size_t)-1 || ack_len == (size_t)-1 ||
            hello_len + ack_len > sizeof(concat) || th_want_len != 32u ||
            psk_len != 32u || an_len != 16u || hn_len != 16u) {
            ok = 0;
        }

        if (!ok) {
            fail_id("[3] protocol vectors", "embedded vector decode");
        } else {
            /* transcript = SHA256(canon(hello) || canon(ack)) over the raw
             * canonical bytes (never the hex text). */
            memcpy(concat, hello, hello_len);
            memcpy(concat + hello_len, ack, ack_len);
            ps4rf_sha256(concat, hello_len + ack_len, th);
            check_bytes("[3] protocol.transcript_sha256 = SHA256(canon(hello) || canon(ack))",
                        th, th_want, 32u);

            /* salt = agent_nonce || host_nonce */
            memcpy(salt, an, an_len);
            memcpy(salt + an_len, hn, hn_len);
            salt_len = an_len + hn_len;

            /* Handshake keys: HKDF-SHA256(ikm = psk, salt, label || transcript, 32). */
            memset(k_hs, 0, sizeof(k_hs));
            for (kc = 0; kc < sizeof(KEY_CASES) / sizeof(KEY_CASES[0]); kc++) {
                int rc;
                label_len = strlen(KEY_CASES[kc].label);
                memcpy(info, KEY_CASES[kc].label, label_len);
                memcpy(info + label_len, th, 32u);
                want_len = unhex(KEY_CASES[kc].want_hex, want, sizeof(want));
                memset(out, 0, sizeof(out));
                rc = ps4rf_hkdf_sha256(psk, psk_len, salt, salt_len,
                                       info, label_len + 32u, out, 32u);
                if (rc != 0 || want_len != 32u) {
                    fail_id(KEY_CASES[kc].id, rc != 0 ? "hkdf returned non-zero" : "vector decode");
                    continue;
                }
                check_bytes(KEY_CASES[kc].id, out, want, 32u);
                if (kc == 0u) {
                    memcpy(k_hs, out, 32u);
                }
            }

            /* Nonce prefixes: out_len 4, enum-NAME info spelling (frozen). */
            for (kc = 0; kc < sizeof(NP_CASES) / sizeof(NP_CASES[0]); kc++) {
                int rc;
                uint8_t prefix[4], prefix_want[4];
                size_t prefix_want_len;
                label_len = strlen(NP_CASES[kc].label);
                memcpy(info, NP_CASES[kc].label, label_len);
                memcpy(info + label_len, th, 32u);
                memset(prefix, 0, sizeof(prefix));
                rc = ps4rf_hkdf_sha256(psk, psk_len, salt, salt_len,
                                       info, label_len + 32u, prefix, 4u);
                prefix_want_len = unhex(NP_CASES[kc].want_hex, prefix_want, sizeof(prefix_want));
                if (rc != 0 || prefix_want_len != 4u) {
                    fail_id(NP_CASES[kc].id, rc != 0 ? "hkdf returned non-zero" : "vector decode");
                    continue;
                }
                check_bytes(NP_CASES[kc].id, prefix, prefix_want, 4u);
            }

            /* Auth proofs: HMAC-SHA256(k_hs, 'ps4rf/proof/<role>/v1' || raw transcript bytes). */
            label_len = strlen(PROOF_LABEL_AGENT);
            memcpy(msg, PROOF_LABEL_AGENT, label_len);
            memcpy(msg + label_len, th, 32u);
            ps4rf_hmac_sha256(k_hs, 32u, msg, label_len + 32u, mac);
            want_len = unhex(PROTO_AUTH_MAC_HEX, want, sizeof(want));
            if (want_len != 32u) {
                fail_id("protocol.exchange.auth_mac_hex", "vector decode");
            } else {
                check_bytes("protocol.exchange.auth_mac_hex = HMAC(k_hs, 'ps4rf/proof/agent/v1' || transcript)",
                            mac, want, 32u);
            }

            label_len = strlen(PROOF_LABEL_HOST);
            memcpy(msg, PROOF_LABEL_HOST, label_len);
            memcpy(msg + label_len, th, 32u);
            ps4rf_hmac_sha256(k_hs, 32u, msg, label_len + 32u, mac);
            want_len = unhex(PROTO_AUTH_ACK_MAC_HEX, want, sizeof(want));
            if (want_len != 32u) {
                fail_id("protocol.exchange.auth_ack_mac_hex", "vector decode");
            } else {
                check_bytes("protocol.exchange.auth_ack_mac_hex = HMAC(k_hs, 'ps4rf/proof/host/v1' || transcript)",
                            mac, want, 32u);
            }
        }
    }

    /* ---------- [4] SHA-256 sanity vectors (well-known digests) ---------- */
    {
        uint8_t got[32], want[32];

        if (unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                  want, sizeof(want)) == 32u) {
            ps4rf_sha256("abc", 3u, got);
            check_bytes("[4] SHA256(\"abc\")", got, want, 32u);
        } else {
            fail_id("[4] SHA256(\"abc\")", "sanity vector decode");
        }
        if (unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  want, sizeof(want)) == 32u) {
            ps4rf_sha256("", 0u, got);
            check_bytes("[4] SHA256(\"\")", got, want, 32u);
        } else {
            fail_id("[4] SHA256(\"\")", "sanity vector decode");
        }
    }

    /* ---------- [5] ps4rf_hkdf_sha256 argument-validation contract ---------- */
    {
        uint8_t buf[32];

        expect_true("[5] hkdf rejects out_len == 0",
                    ps4rf_hkdf_sha256("x", 1u, NULL, 0u, NULL, 0u, buf, 0u) == -1);
        expect_true("[5] hkdf rejects NULL out",
                    ps4rf_hkdf_sha256("x", 1u, NULL, 0u, NULL, 0u, NULL, 32u) == -1);
        expect_true("[5] hkdf rejects out_len > 8160",
                    ps4rf_hkdf_sha256("x", 1u, NULL, 0u, NULL, 0u, buf, 8161u) == -1);
        expect_true("[5] hkdf rejects NULL ikm with non-zero len",
                    ps4rf_hkdf_sha256(NULL, 1u, NULL, 0u, NULL, 0u, buf, 32u) == -1);
        expect_true("[5] hkdf accepts all-empty ikm/salt/info",
                    ps4rf_hkdf_sha256("", 0u, NULL, 0u, NULL, 0u, buf, 32u) == 0);
    }

    printf("\nchecks: %zu, failures: %zu\n", g_checks, g_failures);
    if (g_failures == 0u) {
        printf("RESULT: ALL CHECKS PASSED\n");
        return 0;
    }
    printf("RESULT: FAILURES DETECTED\n");
    return 1;
}
