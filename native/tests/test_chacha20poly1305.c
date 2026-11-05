/*
 * test_chacha20poly1305.c — self-test for the PS4RF native ChaCha20-Poly1305
 * (RFC 8439). Proves byte parity against:
 *
 *   1. RFC 8439 test vectors: section 2.3.2 (block function), 2.4.2 (ChaCha20
 *      cipher), 2.5.2 and appendix A.3 #5..#11 (Poly1305), 2.6.2 (Poly1305 key
 *      generation), 2.8.2 (AEAD_CHACHA20_POLY1305).
 *   2. PS4RF protocol golden vectors from tests/fixtures/crypto/vectors-v1.json
 *      (rfc_vectors.rfc8439_aead and protocol.frames[]): the ciphertext+tag is
 *      reproduced byte for byte, including the reconstructed JCS AAD bytes.
 *   3. Padding edge cases (empty plaintext / empty AAD / length alignment)
 *      whose expected outputs were generated with the Python 'cryptography'
 *      ChaCha20Poly1305 primitive (the byte-parity target).
 *
 * Build (from the repository root):
 *   gcc -std=c99 -O2 -Wall -Wextra -Werror \
 *       -o /tmp/test_chacha native/tests/test_chacha20poly1305.c \
 *       native/src/chacha20poly1305.c
 * Run:
 *   /tmp/test_chacha
 * Exit status is non-zero if any case fails.
 */

#include "../src/chacha20poly1305.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* internal hooks implemented in chacha20poly1305.c (not public API) */
extern int ps4rf_internal_chacha20_block(uint8_t out[64], const uint8_t key[32],
                                         uint32_t counter, const uint8_t nonce[12]);
extern int ps4rf_internal_chacha20_xor(uint8_t *out, const void *in, size_t len,
                                       const uint8_t key[32], uint32_t counter,
                                       const uint8_t nonce[12]);
extern int ps4rf_internal_poly1305(uint8_t tag[16], const uint8_t key[32],
                                   const void *msg, size_t msg_len);

static unsigned g_tests = 0;
static unsigned g_failed = 0;

static void check(const char *name, int ok)
{
    g_tests++;
    if (ok) {
        printf("PASS %s\n", name);
    } else {
        printf("FAIL %s\n", name);
        g_failed++;
    }
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* decode a hex string; returns byte length, or (size_t)-1 on bad input */
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex);
    size_t i;

    if ((n & 1u) != 0u) {
        return (size_t)-1;
    }
    if (n / 2u > cap) {
        return (size_t)-1;
    }
    for (i = 0; i < n; i += 2u) {
        int hi = hex_digit(hex[i]);
        int lo = hex_digit(hex[i + 1u]);
        if (hi < 0 || lo < 0) {
            return (size_t)-1;
        }
        out[i / 2u] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2u;
}

static int dec(const char *hex, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = unhex(hex, out, cap);

    if (n == (size_t)-1) {
        return 0;
    }
    *out_len = n;
    return 1;
}

/* ------------------------------------------------------------------ */
/* RFC 8439 section 2.3.2: ChaCha20 block function                    */
/* ------------------------------------------------------------------ */

static void t_chacha20_block(void)
{
    static const char *KEY =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    static const char *NONCE = "000000090000004a00000000";
    static const char *EXPECT =
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
    uint8_t key[32], nonce[12], expect[64], got[64];
    size_t kl = 0, nl = 0, el = 0;
    int ok = 0;

    if (dec(KEY, key, sizeof(key), &kl) && kl == 32u &&
        dec(NONCE, nonce, sizeof(nonce), &nl) && nl == 12u &&
        dec(EXPECT, expect, sizeof(expect), &el) && el == 64u) {
        if (ps4rf_internal_chacha20_block(got, key, 1u, nonce) == 0 &&
            memcmp(got, expect, 64u) == 0) {
            ok = 1;
        }
    }
    check("rfc8439_2.3.2_chacha20_block", ok);
}

/* ------------------------------------------------------------------ */
/* RFC 8439 section 2.4.2: ChaCha20 encryption (counter starts at 1)  */
/* ------------------------------------------------------------------ */

static void t_chacha20_encrypt(void)
{
    static const char *KEY =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    static const char *NONCE = "000000000000004a00000000";
    static const char *PT =
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e";
    static const char *EXPECT =
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d";
    uint8_t key[32], nonce[12], pt[128], expect[128], got[128];
    size_t kl = 0, nl = 0, pl = 0, el = 0;
    int ok = 0;

    if (dec(KEY, key, sizeof(key), &kl) && kl == 32u &&
        dec(NONCE, nonce, sizeof(nonce), &nl) && nl == 12u &&
        dec(PT, pt, sizeof(pt), &pl) && pl == 114u &&
        dec(EXPECT, expect, sizeof(expect), &el) && el == 114u) {
        if (ps4rf_internal_chacha20_xor(got, pt, pl, key, 1u, nonce) == 0 &&
            memcmp(got, expect, el) == 0) {
            ok = 1;
        }
    }
    check("rfc8439_2.4.2_chacha20_encrypt", ok);
}

/* ------------------------------------------------------------------ */
/* RFC 8439 section 2.5.2: Poly1305                                   */
/* ------------------------------------------------------------------ */

static void t_poly1305_rfc(void)
{
    static const char *KEY =
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
    static const char *MSG =
        "43727970746f6772617068696320466f72756d2052657365617263682047726f7570";
    static const char *TAG = "a8061dc1305136c6c22b8baf0c0127a9";
    uint8_t key[32], msg[64], tag[16], expect[16];
    size_t kl = 0, ml = 0, el = 0;
    int ok = 0;

    if (dec(KEY, key, sizeof(key), &kl) && kl == 32u &&
        dec(MSG, msg, sizeof(msg), &ml) && ml == 34u &&
        dec(TAG, expect, sizeof(expect), &el) && el == 16u) {
        if (ps4rf_internal_poly1305(tag, key, msg, ml) == 0 &&
            memcmp(tag, expect, 16u) == 0) {
            ok = 1;
        }
    }
    check("rfc8439_2.5.2_poly1305", ok);
}

/* ------------------------------------------------------------------ */
/* RFC 8439 appendix A.3, vectors #5..#11 (reduction edge cases)      */
/* ------------------------------------------------------------------ */

static void t_poly1305_edges(void)
{
    static const struct {
        const char *name;
        const char *key; /* R || S, 32 bytes */
        const char *msg;
        const char *tag;
    } V[] = {
        { "rfc8439_a3_poly1305_vector5",
          "0200000000000000000000000000000000000000000000000000000000000000",
          "ffffffffffffffffffffffffffffffff",
          "03000000000000000000000000000000" },
        { "rfc8439_a3_poly1305_vector6",
          "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
          "02000000000000000000000000000000",
          "03000000000000000000000000000000" },
        { "rfc8439_a3_poly1305_vector7",
          "0100000000000000000000000000000000000000000000000000000000000000",
          "ffffffffffffffffffffffffffffffff"
          "f0ffffffffffffffffffffffffffffff"
          "11000000000000000000000000000000",
          "05000000000000000000000000000000" },
        { "rfc8439_a3_poly1305_vector8",
          "0100000000000000000000000000000000000000000000000000000000000000",
          "ffffffffffffffffffffffffffffffff"
          "fbfefefefefefefefefefefefefefefe"
          "01010101010101010101010101010101",
          "00000000000000000000000000000000" },
        { "rfc8439_a3_poly1305_vector9",
          "0200000000000000000000000000000000000000000000000000000000000000",
          "fdffffffffffffffffffffffffffffff",
          "faffffffffffffffffffffffffffffff" },
        { "rfc8439_a3_poly1305_vector10",
          "0100000000000000040000000000000000000000000000000000000000000000",
          "e33594d7505e43b90000000000000000"
          "3394d7505e4379cd0100000000000000"
          "00000000000000000000000000000000"
          "01000000000000000000000000000000",
          "14000000000000005500000000000000" },
        { "rfc8439_a3_poly1305_vector11",
          "0100000000000000040000000000000000000000000000000000000000000000",
          "e33594d7505e43b90000000000000000"
          "3394d7505e4379cd0100000000000000"
          "00000000000000000000000000000000",
          "13000000000000000000000000000000" }
    };
    size_t i;

    for (i = 0u; i < sizeof(V) / sizeof(V[0]); i++) {
        uint8_t key[32], msg[128], tag[16], expect[16];
        size_t kl = 0, ml = 0, el = 0;
        int ok = 0;

        if (dec(V[i].key, key, sizeof(key), &kl) && kl == 32u &&
            dec(V[i].msg, msg, sizeof(msg), &ml) &&
            dec(V[i].tag, expect, sizeof(expect), &el) && el == 16u) {
            if (ps4rf_internal_poly1305(tag, key, msg, ml) == 0 &&
                memcmp(tag, expect, 16u) == 0) {
                ok = 1;
            }
        }
        check(V[i].name, ok);
    }
}

/* ------------------------------------------------------------------ */
/* RFC 8439 section 2.6.2: Poly1305 key generation (block counter 0)  */
/* ------------------------------------------------------------------ */

static void t_key_gen(void)
{
    static const char *KEY =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    static const char *NONCE = "000000000001020304050607";
    static const char *EXPECT =
        "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646";
    uint8_t key[32], nonce[12], block[64], expect[32];
    size_t kl = 0, nl = 0, el = 0;
    int ok = 0;

    if (dec(KEY, key, sizeof(key), &kl) && kl == 32u &&
        dec(NONCE, nonce, sizeof(nonce), &nl) && nl == 12u &&
        dec(EXPECT, expect, sizeof(expect), &el) && el == 32u) {
        if (ps4rf_internal_chacha20_block(block, key, 0u, nonce) == 0 &&
            memcmp(block, expect, 32u) == 0) {
            ok = 1;
        }
    }
    check("rfc8439_2.6.2_poly1305_key_gen", ok);
}

/* ------------------------------------------------------------------ */
/* RFC 8439 section 2.8.2: AEAD seal/open + tamper detection          */
/* ------------------------------------------------------------------ */

static void t_aead_rfc(void)
{
    static const char *KEY =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    static const char *NONCE = "070000004041424344454647";
    static const char *AAD = "50515253c0c1c2c3c4c5c6c7";
    static const char *PT =
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
        "637265656e20776f756c642062652069742e";
    static const char *CT =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116";
    static const char *TAG = "1ae10b594f09e26a7e902ecbd0600691";

    uint8_t key[32], nonce[12], aad[16], pt[128], ct[128], tag[16];
    uint8_t sealed[160], opened[128], tmp[160], bad_aad[16], bad_nonce[12];
    size_t kl = 0, nl = 0, al = 0, pl = 0, cl = 0, tl = 0;
    size_t slen, olen;
    int ok;

    if (!(dec(KEY, key, sizeof(key), &kl) && kl == 32u &&
          dec(NONCE, nonce, sizeof(nonce), &nl) && nl == 12u &&
          dec(AAD, aad, sizeof(aad), &al) && al == 12u &&
          dec(PT, pt, sizeof(pt), &pl) && pl == 114u &&
          dec(CT, ct, sizeof(ct), &cl) && cl == 114u &&
          dec(TAG, tag, sizeof(tag), &tl) && tl == 16u)) {
        check("rfc8439_2.8.2_seal", 0);
        return;
    }

    /* seal must equal ciphertext || tag, byte for byte */
    slen = sizeof(sealed);
    ok = (ps4rf_aead_seal(key, nonce, aad, al, pt, pl, sealed, &slen) == 0) &&
         (slen == pl + 16u) &&
         (memcmp(sealed, ct, cl) == 0) &&
         (memcmp(sealed + cl, tag, tl) == 0);
    check("rfc8439_2.8.2_seal", ok);

    /* open must return the original plaintext */
    olen = sizeof(opened);
    ok = (ps4rf_aead_open(key, nonce, aad, al, sealed, slen, opened, &olen) == 0) &&
         (olen == pl) &&
         (memcmp(opened, pt, pl) == 0);
    check("rfc8439_2.8.2_open", ok);

    /* a single flipped bit in the tag must fail authentication */
    memcpy(tmp, sealed, slen);
    tmp[slen - 1u] ^= 0x01u;
    olen = sizeof(opened);
    ok = (ps4rf_aead_open(key, nonce, aad, al, tmp, slen, opened, &olen) != 0);
    check("rfc8439_2.8.2_tamper_tag", ok);

    /* a single flipped bit in the ciphertext must fail authentication */
    memcpy(tmp, sealed, slen);
    tmp[57] ^= 0x80u;
    olen = sizeof(opened);
    ok = (ps4rf_aead_open(key, nonce, aad, al, tmp, slen, opened, &olen) != 0);
    check("rfc8439_2.8.2_tamper_ciphertext", ok);

    /* a single flipped bit in the AAD must fail authentication */
    memcpy(bad_aad, aad, al);
    bad_aad[0] ^= 0x01u;
    olen = sizeof(opened);
    ok = (ps4rf_aead_open(key, nonce, bad_aad, al, sealed, slen, opened, &olen) != 0);
    check("rfc8439_2.8.2_tamper_aad", ok);

    /* a single flipped bit in the nonce must fail authentication */
    memcpy(bad_nonce, nonce, nl);
    bad_nonce[11] ^= 0x01u;
    olen = sizeof(opened);
    ok = (ps4rf_aead_open(key, bad_nonce, aad, al, sealed, slen, opened, &olen) != 0);
    check("rfc8439_2.8.2_tamper_nonce", ok);
}

/* ------------------------------------------------------------------ */
/* PS4RF protocol golden frames (vectors-v1.json protocol.frames[])   */
/* AAD = JCS bytes of {"direction":...,"message_type":...,            */
/* "protocol_version":1,"sequence":n,"session_id":                   */
/* "SES-0123456789ABCDEF"}  (sorted keys, no spaces).                 */
/* ------------------------------------------------------------------ */

static void t_protocol_frames(void)
{
#define K_H2A "10eca20a4a0ffa654d3c2500ffcbf380d6941987cf8e889771761bcdeee6a1a5"
#define K_A2H "8a6d948229b65edf2fc138805a87a18c136fbe126102cd0bfccf3d446b155d97"

    static const struct {
        const char *name;
        const char *key;
        const char *nonce;
        const char *aad;
        const char *pt;
        const char *ct; /* ciphertext || tag */
    } F[] = {
        { "protocol.h2a_request_seq0", K_H2A,
          "7cf6b6e30000000000000000",
          "7b22646972656374696f6e223a22446972656374696f6e2e484f53545f544f5f"
          "4147454e54222c226d6573736167655f74797065223a2252455155455354222c"
          "2270726f746f636f6c5f76657273696f6e223a312c2273657175656e6365223a"
          "302c2273657373696f6e5f6964223a225345532d303132333435363738394142"
          "43444546227d",
          "7b2270726f6265223a22616561642d6672616d65222c2273657175656e6365223a"
          "302c22746167223a22686f73742d746f2d6167656e74227d",
          "270c95a8c18bce52ff164c9b4a3920e93d616055969ffcc4b3cba4b8d65b5673"
          "e01d6dfefe11fcd7caebd91a45e37513c8a39097c5853649e32571a7dfef2ee2"
          "d7292d2f6269304c57" },
        { "protocol.h2a_request_seq1", K_H2A,
          "7cf6b6e30000000000000001",
          "7b22646972656374696f6e223a22446972656374696f6e2e484f53545f544f5f"
          "4147454e54222c226d6573736167655f74797065223a2252455155455354222c"
          "2270726f746f636f6c5f76657273696f6e223a312c2273657175656e6365223a"
          "312c2273657373696f6e5f6964223a225345532d303132333435363738394142"
          "43444546227d",
          "7b2270726f6265223a22616561642d6672616d65222c2273657175656e6365223a"
          "312c22746167223a22686f73742d746f2d6167656e74227d",
          "a12aefb5e1b99ebb3aebcd7ac6aea37973c59d0047b1f85a0b3dc024b4be66ac"
          "ea78f59666f9240ca9d5589d57a9c7ec06f744f7f972653b9e1f6f9656aa5ec8"
          "b7f91e4a6c7166788d" },
        { "protocol.a2h_response_seq0", K_A2H,
          "6470db330000000000000000",
          "7b22646972656374696f6e223a22446972656374696f6e2e4147454e545f544f5f"
          "484f5354222c226d6573736167655f74797065223a22524553504f4e5345222c"
          "2270726f746f636f6c5f76657273696f6e223a312c2273657175656e6365223a"
          "302c2273657373696f6e5f6964223a225345532d303132333435363738394142"
          "43444546227d",
          "7b2270726f6265223a22616561642d6672616d65222c2273657175656e6365223a"
          "302c22746167223a226167656e742d746f2d686f7374227d",
          "9b0ab113cdb923ca42b167b5654ecb64bffa400491d76191c76800b5f7fdc0f4"
          "15658c1a4474299aa844e4adac0515a867fae0cdf6c669141dba7efa493fce04"
          "c8ec0c22f7ddafaafd" },
        { "protocol.a2h_bye_seq1", K_A2H,
          "6470db330000000000000001",
          "7b22646972656374696f6e223a22446972656374696f6e2e4147454e545f544f5f"
          "484f5354222c226d6573736167655f74797065223a22425945222c2270726f74"
          "6f636f6c5f76657273696f6e223a312c2273657175656e6365223a312c227365"
          "7373696f6e5f6964223a225345532d3031323334353637383941424344454622"
          "7d",
          "7b2270726f6265223a22616561642d6672616d65222c2273657175656e6365223a"
          "312c22746167223a226167656e742d746f2d686f7374227d",
          "b819c89e5fc02437fd8dc7c730fe40adc719459bfee318646a5aa802509c2a88"
          "c654d9a85be107072ee3ad149876d6ad22cc58855ca641286fd67275849cb0ea"
          "f1cc86290835fc243c" }
    };
    size_t i;

    for (i = 0u; i < sizeof(F) / sizeof(F[0]); i++) {
        uint8_t key[32], nonce[12], aad[256], pt[128], ct[128];
        uint8_t sealed[256], opened[128];
        size_t kl = 0, nl = 0, al = 0, pl = 0, cl = 0;
        size_t slen, olen;
        char name[96];
        int ok;

        if (!(dec(F[i].key, key, sizeof(key), &kl) && kl == 32u &&
              dec(F[i].nonce, nonce, sizeof(nonce), &nl) && nl == 12u &&
              dec(F[i].aad, aad, sizeof(aad), &al) &&
              dec(F[i].pt, pt, sizeof(pt), &pl) &&
              dec(F[i].ct, ct, sizeof(ct), &cl) && cl == pl + 16u)) {
            check(F[i].name, 0);
            continue;
        }

        snprintf(name, sizeof(name), "%s.seal", F[i].name);
        slen = sizeof(sealed);
        ok = (ps4rf_aead_seal(key, nonce, aad, al, pt, pl, sealed, &slen) == 0) &&
             (slen == cl) &&
             (memcmp(sealed, ct, cl) == 0);
        check(name, ok);

        snprintf(name, sizeof(name), "%s.open", F[i].name);
        olen = sizeof(opened);
        ok = (ps4rf_aead_open(key, nonce, aad, al, ct, cl, opened, &olen) == 0) &&
             (olen == pl) &&
             (memcmp(opened, pt, pl) == 0);
        check(name, ok);
    }
}

/* ------------------------------------------------------------------ */
/* Padding edge cases (expected = Python 'cryptography' output)       */
/* ------------------------------------------------------------------ */

static void t_padding_edges(void)
{
    static const char *KEY =
        "10eca20a4a0ffa654d3c2500ffcbf380d6941987cf8e889771761bcdeee6a1a5";
    static const char *NONCE = "000102030405060708090a0b";

    static const struct {
        const char *name;
        const char *aad;
        const char *pt;
        const char *out; /* ciphertext || tag */
    } E[] = {
        { "edge_empty_pt_empty_aad", "", "",
          "093561d01cb8f1bf4c886ac7a0259e00" },
        { "edge_aad1_pt1", "41", "42",
          "776634823f389c757d11d2808d635d98d2" },
        { "edge_aad16_pt16",
          "000102030405060708090a0b0c0d0e0f",
          "101112131415161718191a1b1c1d1e1f",
          "25d802150f6d2fa9784f24ce9a1e12bd5ef5d134a82cbc79b717d9d2b345803a" },
        { "edge_aad15_pt17",
          "000102030405060708090a0b0c0d0e",
          "808182838485868788898a8b8c8d8e8f90",
          "b54892859ffdbf39e8dfb45e0a8e822dce03293e1ec750156a1d961206a2c16773" },
        { "edge_empty_pt_aad13",
          "01010101010101010101010101", "",
          "f020d9f53297e9d087d037fcdb64cc77" },
        { "edge_pt13_empty_aad", "",
          "02020202020202020202020202",
          "37cb1204197a3bbc62543cd784f000a047d31eee834b4cf7b473e0050c" }
    };
    size_t i;

    for (i = 0u; i < sizeof(E) / sizeof(E[0]); i++) {
        uint8_t key[32], nonce[12], aad[64], pt[64], expect[128];
        uint8_t sealed[128], opened[64];
        size_t kl = 0, nl = 0, al = 0, pl = 0, el = 0;
        size_t slen, olen;
        char name[96];
        int ok;

        if (!(dec(KEY, key, sizeof(key), &kl) && kl == 32u &&
              dec(NONCE, nonce, sizeof(nonce), &nl) && nl == 12u &&
              dec(E[i].aad, aad, sizeof(aad), &al) &&
              dec(E[i].pt, pt, sizeof(pt), &pl) &&
              dec(E[i].out, expect, sizeof(expect), &el) && el == pl + 16u)) {
            check(E[i].name, 0);
            continue;
        }

        snprintf(name, sizeof(name), "%s.seal", E[i].name);
        slen = sizeof(sealed);
        ok = (ps4rf_aead_seal(key, nonce, aad, al, pt, pl, sealed, &slen) == 0) &&
             (slen == el) &&
             (memcmp(sealed, expect, el) == 0);
        check(name, ok);

        snprintf(name, sizeof(name), "%s.open", E[i].name);
        olen = sizeof(opened);
        ok = (ps4rf_aead_open(key, nonce, aad, al, sealed, el, opened, &olen) == 0) &&
             (olen == pl) &&
             (memcmp(opened, pt, pl) == 0);
        check(name, ok);
    }
}

/* ------------------------------------------------------------------ */
/* argument validation                                                */
/* ------------------------------------------------------------------ */

static void t_invalid_args(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t pt[8];
    uint8_t ct[64];
    uint8_t ptout[64];
    size_t len;

    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(pt, 0x33, sizeof(pt));
    memset(ct, 0x44, sizeof(ct));

    len = sizeof(ct);
    check("args.seal_null_key",
          ps4rf_aead_seal(NULL, nonce, NULL, 0u, pt, sizeof(pt), ct, &len) == -1);

    len = sizeof(ct);
    check("args.seal_null_out",
          ps4rf_aead_seal(key, nonce, NULL, 0u, pt, sizeof(pt), NULL, &len) == -1);

    len = 8u; /* needs 8 + 16 = 24 */
    check("args.seal_small_output",
          ps4rf_aead_seal(key, nonce, NULL, 0u, pt, sizeof(pt), ct, &len) == -1);

    len = sizeof(ptout);
    check("args.open_short_ct",
          ps4rf_aead_open(key, nonce, NULL, 0u, ct, 15u, ptout, &len) == -1);

    len = sizeof(ptout);
    check("args.open_null_ptout",
          ps4rf_aead_open(key, nonce, NULL, 0u, ct, 32u, NULL, &len) == -1);
}

int main(void)
{
    t_chacha20_block();
    t_chacha20_encrypt();
    t_poly1305_rfc();
    t_poly1305_edges();
    t_key_gen();
    t_aead_rfc();
    t_protocol_frames();
    t_padding_edges();
    t_invalid_args();

    printf("---\n");
    if (g_failed == 0u) {
        printf("ALL %u TESTS PASSED\n", g_tests);
        return 0;
    }
    printf("%u of %u TESTS FAILED\n", g_failed, g_tests);
    return 1;
}
