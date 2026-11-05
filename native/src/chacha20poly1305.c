/*
 * chacha20poly1305.c — PS4RF native agent: self-contained ChaCha20-Poly1305
 * AEAD implementation per RFC 8439.
 *
 * Characteristics:
 *   - C99, no external libraries, no heap, no I/O, no subprocesses.
 *   - Byte-for-byte compatible with the Python 'cryptography' library's
 *     ChaCha20Poly1305 primitive (seal output layout: ciphertext || tag).
 *   - Zero-length plaintext and zero-length AAD, and AAD/ciphertext lengths
 *     that are not multiples of 16, are handled with the RFC 8439 section
 *     2.8 padding rules.
 *   - The tag check is constant time: every tag byte is examined, there is
 *     no early exit on the first difference.
 *   - Plaintext lengths beyond the 32-bit ChaCha20 block counter range
 *     ((2^32 - 1) * 64 bytes) are rejected as invalid arguments, so the
 *     block counter can never wrap.
 *   - The only language extension used is `unsigned __int128` (supported by
 *     GCC and Clang on 64-bit targets) for 64x64 -> 128-bit products. All
 *     other code is plain C99.
 *
 * AEAD buffer fed to Poly1305 (RFC 8439 section 2.8):
 *     aad || pad16(aad) || ciphertext || pad16(ciphertext) ||
 *     le64(aad_len) || le64(ct_len)
 */

#include "chacha20poly1305.h"

#include <string.h>

/* ---------------------------------------------------------------------- */
/* internal hooks used by the native self-test (not part of the header)   */
/* ---------------------------------------------------------------------- */

int ps4rf_internal_chacha20_block(uint8_t out[64], const uint8_t key[32],
                                  uint32_t counter, const uint8_t nonce[12]);
int ps4rf_internal_chacha20_xor(uint8_t *out, const void *in, size_t len,
                                const uint8_t key[32], uint32_t counter,
                                const uint8_t nonce[12]);
int ps4rf_internal_poly1305(uint8_t tag[16], const uint8_t key[32],
                            const void *msg, size_t msg_len);

/* RFC 8439 section 2.8: at most 2^32-1 blocks of 64 bytes per invocation. */
#define PS4RF_MAX_PT_LEN (((uint64_t)0xFFFFFFFFu) * 64u)

/* ---------------------------------------------------------------------- */
/* byte-order and zeroization helpers                                     */
/* ---------------------------------------------------------------------- */

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint64_t load64_le(const uint8_t *p)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < 8u; i++) {
        v |= (uint64_t)p[i] << (8u * i);
    }
    return v;
}

static void store64_le(uint8_t *p, uint64_t v)
{
    unsigned i;
    for (i = 0; i < 8u; i++) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

/* best-effort secret wiping that survives -O2 (volatile stores) */
static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n > 0u) {
        *vp++ = 0u;
        n--;
    }
}

/* ---------------------------------------------------------------------- */
/* ChaCha20 (RFC 8439 sections 2.1 - 2.4)                                 */
/* ---------------------------------------------------------------------- */

#define CHACHA_QUARTERROUND(a, b, c, d)                                 \
    do {                                                                \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 16u);           \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 12u);           \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 8u);            \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 7u);            \
    } while (0)

/* One 64-byte ChaCha20 keystream block (RFC 8439 section 2.3). */
static void chacha20_block(uint8_t out[64], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12])
{
    static const uint32_t constants[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t x[16];
    uint32_t initial[16];
    unsigned i;

    for (i = 0; i < 4u; i++) {
        initial[i] = constants[i];
    }
    for (i = 0; i < 8u; i++) {
        initial[4u + i] = load32_le(key + 4u * i);
    }
    initial[12] = counter;
    for (i = 0; i < 3u; i++) {
        initial[13u + i] = load32_le(nonce + 4u * i);
    }
    memcpy(x, initial, sizeof(x));

    for (i = 0; i < 10u; i++) {
        CHACHA_QUARTERROUND(0, 4, 8, 12);
        CHACHA_QUARTERROUND(1, 5, 9, 13);
        CHACHA_QUARTERROUND(2, 6, 10, 14);
        CHACHA_QUARTERROUND(3, 7, 11, 15);
        CHACHA_QUARTERROUND(0, 5, 10, 15);
        CHACHA_QUARTERROUND(1, 6, 11, 12);
        CHACHA_QUARTERROUND(2, 7, 8, 13);
        CHACHA_QUARTERROUND(3, 4, 9, 14);
    }
    for (i = 0; i < 16u; i++) {
        store32_le(out + 4u * i, x[i] + initial[i]);
    }
}

#undef CHACHA_QUARTERROUND

/* XOR `len` bytes with the ChaCha20 keystream starting at block `counter`.
 * In-place operation (out == in) is safe. The caller guarantees the block
 * counter cannot overflow: len <= PS4RF_MAX_PT_LEN. */
static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32], uint32_t counter,
                         const uint8_t nonce[12])
{
    uint8_t ks[64];
    size_t off = 0;

    while (off < len) {
        size_t n = len - off;
        size_t i;

        if (n > sizeof(ks)) {
            n = sizeof(ks);
        }
        chacha20_block(ks, key, counter, nonce);
        for (i = 0; i < n; i++) {
            out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        }
        off += n;
        counter++;
    }
}

/* ---------------------------------------------------------------------- */
/* Poly1305 (RFC 8439 section 2.5)                                        */
/*                                                                        */
/* The 130-bit accumulator is kept in three little-endian 64-bit limbs    */
/* h = h0 + h1*2^64 + h2*2^128, normalized so that h2 < 4. Reduction      */
/* exploits 2^130 == 5 (mod 2^130 - 5):                                   */
/*   - a limb at 2^192 folds as 2^192 = 2^62 * 2^130 -> multiply by       */
/*     5 * 2^62                                                           */
/*   - bits of h2 at or above 2^130 fold with factor 5                    */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint64_t r0, r1;     /* clamped one-time key r (little-endian)        */
    uint64_t s0, s1;     /* one-time key s (little-endian)                */
    uint64_t h0, h1, h2; /* accumulator limbs                             */
    uint8_t  buf[16];    /* pending bytes of a partial block              */
    size_t   buf_len;    /* number of pending bytes, 0..15                */
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32])
{
    uint64_t t0 = load64_le(key);
    uint64_t t1 = load64_le(key + 8);

    /* clamp r: r[3], r[7], r[11], r[15] &= 15; r[4], r[8], r[12] &= 252 */
    st->r0 = t0 & UINT64_C(0x0ffffffc0fffffff);
    st->r1 = t1 & UINT64_C(0x0ffffffc0ffffffc);
    st->s0 = load64_le(key + 16);
    st->s1 = load64_le(key + 24);
    st->h0 = 0;
    st->h1 = 0;
    st->h2 = 0;
    st->buf_len = 0;
}

/* Fold h2 >= 4 (bits at or above 2^130) back with factor 5 and propagate
 * carries. Accepts any h2 < 2^64; the carry contribution is handled with
 * 128-bit arithmetic. Exits with h2 < 4. */
static void poly1305_reduce_130(uint64_t *h0p, uint64_t *h1p, uint64_t *h2p)
{
    uint64_t h0 = *h0p;
    uint64_t h1 = *h1p;
    uint64_t h2 = *h2p;

    while (h2 >= 4u) {
        uint64_t carry = h2 >> 2;
        unsigned __int128 t;

        h2 &= 3u;
        t = (unsigned __int128)h0 + (unsigned __int128)carry * 5u;
        h0 = (uint64_t)t;
        t = (unsigned __int128)h1 + (t >> 64);
        h1 = (uint64_t)t;
        h2 += (uint64_t)(t >> 64);
    }
    *h0p = h0;
    *h1p = h1;
    *h2p = h2;
}

/* h = (h + block) * r mod (2^130 - 5) for one 16-byte block.
 * b2add is 1 for full 16-byte blocks (the 2^128 bit); the final partial
 * block contributes its 2^(8n) bit through the padded buffer instead. */
static void poly1305_block(poly1305_state *st, uint64_t b0, uint64_t b1,
                           uint64_t b2add)
{
    unsigned __int128 t;
    unsigned __int128 t0, t1, t2, t3;
    uint64_t l0, l1, l2, l3;

    /* h += block */
    t = (unsigned __int128)st->h0 + b0;
    st->h0 = (uint64_t)t;
    t = (unsigned __int128)st->h1 + b1 + (t >> 64);
    st->h1 = (uint64_t)t;
    t = (unsigned __int128)st->h2 + b2add + (t >> 64);
    st->h2 = (uint64_t)t;
    poly1305_reduce_130(&st->h0, &st->h1, &st->h2);

    /* h *= r: (h0 + h1*2^64 + h2*2^128) * (r0 + r1*2^64) */
    t0 = (unsigned __int128)st->h0 * st->r0;
    t1 = (unsigned __int128)st->h0 * st->r1 + (unsigned __int128)st->h1 * st->r0;
    t2 = (unsigned __int128)st->h1 * st->r1 + (unsigned __int128)st->h2 * st->r0;
    t3 = (unsigned __int128)st->h2 * st->r1;

    t = t0; l0 = (uint64_t)t; t >>= 64;
    t += t1; l1 = (uint64_t)t; t >>= 64;
    t += t2; l2 = (uint64_t)t; t >>= 64;
    t += t3; l3 = (uint64_t)t; /* l3 < 2^63: 5*l3 << 62 cannot overflow 128 bits */

    /* fold the 2^192 limb: 2^192 = 2^62 * 2^130 == 5 * 2^62 (mod p).
     * l3 shrinks to <= 1 after the first pass, so this terminates quickly. */
    while (l3 != 0u) {
        unsigned __int128 red = ((unsigned __int128)l3 * 5u) << 62;

        t = (unsigned __int128)l0 + red; l0 = (uint64_t)t; t >>= 64;
        t += (unsigned __int128)l1; l1 = (uint64_t)t; t >>= 64;
        t += (unsigned __int128)l2; l2 = (uint64_t)t; t >>= 64;
        l3 = (uint64_t)t;
    }
    poly1305_reduce_130(&l0, &l1, &l2);
    st->h0 = l0;
    st->h1 = l1;
    st->h2 = l2;
}

/* Process floor(len/16) full 16-byte blocks taken directly from `m`. */
static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t len)
{
    size_t i;

    for (i = 0; i + 16u <= len; i += 16u) {
        poly1305_block(st, load64_le(m + i), load64_le(m + i + 8), 1u);
    }
}

static void poly1305_update(poly1305_state *st, const void *data, size_t len)
{
    const uint8_t *m = (const uint8_t *)data;

    if (len == 0u) {
        return;
    }
    if (st->buf_len > 0u) {
        size_t take = 16u - st->buf_len;

        if (take > len) {
            take = len;
        }
        memcpy(st->buf + st->buf_len, m, take);
        st->buf_len += take;
        m += take;
        len -= take;
        if (st->buf_len == 16u) {
            poly1305_block(st, load64_le(st->buf), load64_le(st->buf + 8), 1u);
            st->buf_len = 0u;
        }
    }
    if (len >= 16u) {
        size_t full = len & ~(size_t)15u;

        poly1305_blocks(st, m, full);
        m += full;
        len -= full;
    }
    if (len > 0u) {
        memcpy(st->buf, m, len);
        st->buf_len = len;
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t tag[16])
{
    uint64_t h0, h1, h2, g0, g1, g2, mask, r0, r1;
    uint64_t c0, c1, csum;

    if (st->buf_len > 0u) {
        uint8_t blk[16];
        unsigned i;

        for (i = 0; i < 16u; i++) {
            blk[i] = 0u;
        }
        memcpy(blk, st->buf, st->buf_len);
        blk[st->buf_len] = 1u; /* the appended 2^(8n) bit */
        poly1305_block(st, load64_le(blk), load64_le(blk + 8), 0u);
    }

    h0 = st->h0;
    h1 = st->h1;
    h2 = st->h2;

    /* fully reduce mod p: g = h - p, with p = 4*2^128 - 5, computed as
     * g0 = h0 + 5 (carry c0), g1 = h1 + c0 (carry c1), g2 = h2 + c1 - 4.
     * g is valid iff h2 + c1 >= 4 (then g2 has no borrow). Constant time. */
    g0 = h0 + 5u;
    c0 = (g0 < h0) ? 1u : 0u;
    g1 = h1 + c0;
    c1 = (g1 < h1) ? 1u : 0u;
    csum = h2 + c1;
    g2 = csum - 4u;
    mask = (csum >= 4u) ? UINT64_MAX : 0u;
    h0 = (g0 & mask) | (h0 & ~mask);
    h1 = (g1 & mask) | (h1 & ~mask);
    h2 = (g2 & mask) | (h2 & ~mask);

    /* tag = (h + s) mod 2^128 */
    r0 = h0 + st->s0;
    r1 = h1 + st->s1 + ((r0 < h0) ? 1u : 0u);
    store64_le(tag, r0);
    store64_le(tag + 8, r1);

    secure_zero(st, sizeof(*st));
}

/* ---------------------------------------------------------------------- */
/* AEAD construction (RFC 8439 section 2.8)                               */
/* ---------------------------------------------------------------------- */

/* constant-time 16-byte comparison: 1 if equal, 0 otherwise. Every byte is
 * read; there is no early exit. */
static int ct_memequal(const uint8_t *a, const uint8_t *b, size_t n)
{
    volatile uint8_t acc = 0u;
    size_t i;

    for (i = 0; i < n; i++) {
        acc = (uint8_t)(acc | (a[i] ^ b[i]));
    }
    return (int)(acc == 0u);
}

int ps4rf_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const void *aad, size_t aad_len,
                    const void *pt, size_t pt_len, void *ct_out, size_t *ct_len_io)
{
    static const uint8_t zeros[16] = { 0u };
    uint8_t otk[64]; /* first 32 bytes are the Poly1305 one-time key */
    uint8_t tag[16];
    uint8_t lens[16];
    poly1305_state st;
    size_t pad;

    if (key == NULL || nonce == NULL) {
        return -1;
    }
    if (ct_out == NULL || ct_len_io == NULL) {
        return -1;
    }
    if (pt == NULL && pt_len != 0u) {
        return -1;
    }
    if (aad == NULL && aad_len != 0u) {
        return -1;
    }
    if ((uint64_t)pt_len > PS4RF_MAX_PT_LEN) {
        return -1;
    }
    if (pt_len > SIZE_MAX - 16u) {
        return -1;
    }
    if (*ct_len_io < pt_len + 16u) {
        return -1;
    }

    /* one-time Poly1305 key = first 32 bytes of ChaCha20 block 0 */
    chacha20_block(otk, key, 0u, nonce);

    poly1305_init(&st, otk);
    if (aad_len > 0u) {
        poly1305_update(&st, aad, aad_len);
    }
    pad = aad_len & 15u;
    if (pad != 0u) {
        poly1305_update(&st, zeros, 16u - pad);
    }

    if (pt_len > 0u) {
        chacha20_xor((uint8_t *)ct_out, (const uint8_t *)pt, pt_len, key, 1u, nonce);
        poly1305_update(&st, ct_out, pt_len);
    }
    pad = pt_len & 15u;
    if (pad != 0u) {
        poly1305_update(&st, zeros, 16u - pad);
    }

    store64_le(lens, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)pt_len);
    poly1305_update(&st, lens, 16u);

    poly1305_finish(&st, tag);
    memcpy((uint8_t *)ct_out + pt_len, tag, 16u);
    *ct_len_io = pt_len + 16u;

    secure_zero(otk, sizeof(otk));
    return 0;
}

int ps4rf_aead_open(const uint8_t key[32], const uint8_t nonce[12], const void *aad, size_t aad_len,
                    const void *ct, size_t ct_len, void *pt_out, size_t *pt_len_io)
{
    static const uint8_t zeros[16] = { 0u };
    uint8_t otk[64]; /* first 32 bytes are the Poly1305 one-time key */
    uint8_t tag[16];
    uint8_t lens[16];
    poly1305_state st;
    size_t pt_len;
    size_t pad;

    if (key == NULL || nonce == NULL) {
        return -1;
    }
    if (ct == NULL || pt_len_io == NULL) {
        return -1;
    }
    if (aad == NULL && aad_len != 0u) {
        return -1;
    }
    if (ct_len < 16u) {
        return -1;
    }
    pt_len = ct_len - 16u;
    if (pt_out == NULL && pt_len != 0u) {
        return -1;
    }
    if ((uint64_t)pt_len > PS4RF_MAX_PT_LEN) {
        return -1;
    }
    if (*pt_len_io < pt_len) {
        return -1;
    }

    chacha20_block(otk, key, 0u, nonce);

    poly1305_init(&st, otk);
    if (aad_len > 0u) {
        poly1305_update(&st, aad, aad_len);
    }
    pad = aad_len & 15u;
    if (pad != 0u) {
        poly1305_update(&st, zeros, 16u - pad);
    }
    if (pt_len > 0u) {
        poly1305_update(&st, ct, pt_len);
    }
    pad = pt_len & 15u;
    if (pad != 0u) {
        poly1305_update(&st, zeros, 16u - pad);
    }

    store64_le(lens, (uint64_t)aad_len);
    store64_le(lens + 8, (uint64_t)pt_len);
    poly1305_update(&st, lens, 16u);

    poly1305_finish(&st, tag);

    /* verify BEFORE releasing any plaintext; constant time */
    if (!ct_memequal(tag, (const uint8_t *)ct + pt_len, 16u)) {
        secure_zero(otk, sizeof(otk));
        return -1;
    }

    if (pt_len > 0u) {
        chacha20_xor((uint8_t *)pt_out, (const uint8_t *)ct, pt_len, key, 1u, nonce);
    }
    *pt_len_io = pt_len;

    secure_zero(otk, sizeof(otk));
    return 0;
}

/* ---------------------------------------------------------------------- */
/* internal hooks (used by native/tests/test_chacha20poly1305.c)          */
/* ---------------------------------------------------------------------- */

int ps4rf_internal_chacha20_block(uint8_t out[64], const uint8_t key[32],
                                  uint32_t counter, const uint8_t nonce[12])
{
    if (out == NULL || key == NULL || nonce == NULL) {
        return -1;
    }
    chacha20_block(out, key, counter, nonce);
    return 0;
}

int ps4rf_internal_chacha20_xor(uint8_t *out, const void *in, size_t len,
                                const uint8_t key[32], uint32_t counter,
                                const uint8_t nonce[12])
{
    if (key == NULL || nonce == NULL) {
        return -1;
    }
    if (len == 0u) {
        return 0;
    }
    if (out == NULL || in == NULL) {
        return -1;
    }
    if ((uint64_t)len > PS4RF_MAX_PT_LEN) {
        return -1;
    }
    chacha20_xor(out, (const uint8_t *)in, len, key, counter, nonce);
    return 0;
}

int ps4rf_internal_poly1305(uint8_t tag[16], const uint8_t key[32],
                            const void *msg, size_t msg_len)
{
    poly1305_state st;

    if (tag == NULL || key == NULL) {
        return -1;
    }
    if (msg == NULL && msg_len != 0u) {
        return -1;
    }
    poly1305_init(&st, key);
    if (msg_len > 0u) {
        poly1305_update(&st, msg, msg_len);
    }
    poly1305_finish(&st, tag);
    return 0;
}
