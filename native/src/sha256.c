/*
 * sha256.c -- self-contained SHA-256, HMAC-SHA256 and HKDF-SHA256 (C99).
 *
 * PS4RF native agent (W2 native crypto core). No external dependencies:
 * the only standard-library include is <string.h> (memcpy/memset).
 *
 * Algorithms: FIPS 180-4 (SHA-256), RFC 2104 (HMAC), RFC 5869 (HKDF).
 */

#include "sha256.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-256 core                                                        */
/* ------------------------------------------------------------------ */

#define PS4RF_ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t PS4RF_SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t PS4RF_SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static void ps4rf_sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = PS4RF_ROTR32(w[i - 15], 7) ^ PS4RF_ROTR32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = PS4RF_ROTR32(w[i - 2], 17) ^ PS4RF_ROTR32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        uint32_t big_s1 = PS4RF_ROTR32(e, 6) ^ PS4RF_ROTR32(e, 11) ^
                          PS4RF_ROTR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + big_s1 + ch + PS4RF_SHA256_K[i] + w[i];
        uint32_t big_s0 = PS4RF_ROTR32(a, 2) ^ PS4RF_ROTR32(a, 13) ^
                          PS4RF_ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = big_s0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

typedef struct {
    uint32_t state[8];
    uint64_t total;      /* total message bytes fed so far */
    uint8_t buf[64];     /* partial block */
    size_t buf_len;
} ps4rf_sha256_ctx;

static void ps4rf_sha256_init(ps4rf_sha256_ctx *ctx)
{
    memcpy(ctx->state, PS4RF_SHA256_IV, sizeof(PS4RF_SHA256_IV));
    ctx->total = 0u;
    ctx->buf_len = 0u;
}

static void ps4rf_sha256_update(ps4rf_sha256_ctx *ctx, const uint8_t *data,
                                size_t len)
{
    ctx->total += (uint64_t)len;
    while (len > 0u) {
        size_t take = 64u - ctx->buf_len;
        if (take > len) {
            take = len;
        }
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 64u) {
            ps4rf_sha256_compress(ctx->state, ctx->buf);
            ctx->buf_len = 0u;
        }
    }
}

static void ps4rf_sha256_final(ps4rf_sha256_ctx *ctx, uint8_t out[32])
{
    uint64_t bits = ctx->total * 8u;
    uint8_t pad[128];
    size_t pad_len, i;

    /* 0x80, then zeros up to 8 bytes short of a block boundary, then the
     * 64-bit big-endian message length in bits. */
    pad_len = (ctx->buf_len < 56u) ? (64u - ctx->buf_len)
                                   : (128u - ctx->buf_len);
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80u;
    for (i = 0; i < 8u; i++) {
        pad[pad_len - 8u + i] = (uint8_t)(bits >> (56u - 8u * i));
    }
    ps4rf_sha256_update(ctx, pad, pad_len);

    for (i = 0; i < 8u; i++) {
        out[i * 4u] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4u + 1u] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4u + 2u] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4u + 3u] = (uint8_t)(ctx->state[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Public interface                                                    */
/* ------------------------------------------------------------------ */

void ps4rf_sha256(const void *data, size_t len, uint8_t out[32])
{
    ps4rf_sha256_ctx ctx;

    ps4rf_sha256_init(&ctx);
    ps4rf_sha256_update(&ctx, (const uint8_t *)data, len);
    ps4rf_sha256_final(&ctx, out);
}

/* Streaming HMAC-SHA256 (RFC 2104). Internal; lets HKDF feed
 * T(i-1) || info || i as successive update calls, so `info` never needs
 * to sit in one contiguous buffer next to T(i-1). */
typedef struct {
    ps4rf_sha256_ctx inner;
    uint8_t opad[64];
} ps4rf_hmac_ctx;

static void ps4rf_hmac_init(ps4rf_hmac_ctx *hc, const uint8_t *key,
                            size_t key_len)
{
    uint8_t k[64];
    uint8_t ipad[64];
    size_t i;

    memset(k, 0, sizeof(k));
    if (key_len > sizeof(k)) {
        /* RFC 2104: keys longer than the block size are hashed first. */
        ps4rf_sha256(key, key_len, k);
    } else if (key_len > 0u) {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < sizeof(k); i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        hc->opad[i] = (uint8_t)(k[i] ^ 0x5cu);
    }

    ps4rf_sha256_init(&hc->inner);
    ps4rf_sha256_update(&hc->inner, ipad, sizeof(ipad));

    memset(k, 0, sizeof(k));
    memset(ipad, 0, sizeof(ipad));
}

static void ps4rf_hmac_update(ps4rf_hmac_ctx *hc, const uint8_t *data,
                              size_t len)
{
    ps4rf_sha256_update(&hc->inner, data, len);
}

static void ps4rf_hmac_final(ps4rf_hmac_ctx *hc, uint8_t out[32])
{
    uint8_t inner[32];
    ps4rf_sha256_ctx outer;

    ps4rf_sha256_final(&hc->inner, inner);

    ps4rf_sha256_init(&outer);
    ps4rf_sha256_update(&outer, hc->opad, sizeof(hc->opad));
    ps4rf_sha256_update(&outer, inner, sizeof(inner));
    ps4rf_sha256_final(&outer, out);

    memset(inner, 0, sizeof(inner));
    memset(hc->opad, 0, sizeof(hc->opad));
}

void ps4rf_hmac_sha256(const void *key, size_t key_len,
                       const void *msg, size_t msg_len, uint8_t out[32])
{
    ps4rf_hmac_ctx hc;

    ps4rf_hmac_init(&hc, (const uint8_t *)key, key_len);
    ps4rf_hmac_update(&hc, (const uint8_t *)msg, msg_len);
    ps4rf_hmac_final(&hc, out);
}

int ps4rf_hkdf_sha256(const void *ikm, size_t ikm_len,
                      const void *salt, size_t salt_len,
                      const void *info, size_t info_len,
                      void *out, size_t out_len)
{
    uint8_t prk[32];
    uint8_t t[32];
    uint8_t zero_salt[32];
    uint8_t counter;
    uint8_t *o = (uint8_t *)out;
    size_t t_len = 0u;
    size_t done = 0u;

    if (out == NULL || out_len == 0u || out_len > 255u * 32u) {
        return -1;
    }
    if ((ikm == NULL && ikm_len > 0u) ||
        (salt == NULL && salt_len > 0u) ||
        (info == NULL && info_len > 0u)) {
        return -1;
    }

    /* Extract: PRK = HMAC-SHA256(salt, IKM). An absent salt is HashLen
     * (32) zero bytes per RFC 5869 section 2.2. */
    if (salt_len == 0u) {
        memset(zero_salt, 0, sizeof(zero_salt));
        ps4rf_hmac_sha256(zero_salt, sizeof(zero_salt), ikm, ikm_len, prk);
    } else {
        ps4rf_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }

    /* Expand: T(0) = empty; T(i) = HMAC-SHA256(PRK, T(i-1) || info || i),
     * for i = 1..255; OKM = first out_len bytes of T(1) || T(2) || ... */
    memset(t, 0, sizeof(t));
    for (counter = 1u; done < out_len; counter++) {
        ps4rf_hmac_ctx hc;
        size_t take = out_len - done;
        if (take > 32u) {
            take = 32u;
        }
        ps4rf_hmac_init(&hc, prk, sizeof(prk));
        ps4rf_hmac_update(&hc, t, t_len);
        ps4rf_hmac_update(&hc, (const uint8_t *)info, info_len);
        ps4rf_hmac_update(&hc, &counter, 1u);
        ps4rf_hmac_final(&hc, t);
        t_len = 32u;
        memcpy(o + done, t, take);
        done += take;
    }

    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    return 0;
}
