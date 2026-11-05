/* PS4RF W2 parity harness (offline, no console, no live target).
 *
 *   native input vector -> native output -> compare against golden expected bytes
 *
 * Reads the two normative catalogs and the generated negative/boundary script
 * catalog, runs every vector through the native protocol core and reports
 * per-vector PASS/FAIL with the first differing offset. Exit code 0 only when
 * every executed vector passed.
 *
 * Stages: canonicalization, transcript, hkdf, aad, nonce, aead, frame_header,
 * wire_frame, handshake.
 */
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "chacha20poly1305.h"
#include "jcs.h"
#include "ps4rf_protocol.h"
#include "sha256.h"

/* --------------------------------------------------------------- reporting */

static const char *STAGES[] = {"canonicalization", "transcript", "hkdf", "aad",  "nonce",
                               "aead",             "frame_header", "wire_frame", "handshake"};
#define STAGE_COUNT ((int)(sizeof(STAGES) / sizeof(STAGES[0])))

static int stage_index(const char *name)
{
    int i;
    for (i = 0; i < STAGE_COUNT; i++)
        if (strcmp(STAGES[i], name) == 0) return i;
    return -1;
}

static int counts[STAGE_COUNT][3]; /* 0 pass, 1 fail, 2 skip */
static int total_fail = 0;
static int verbose = 0;

/* NULL-safe string for report/printf paths. */
static const char *nn(const char *s)
{
    return s != NULL ? s : "?";
}

static void report(const char *stage, const char *vector_id, int outcome,
                   const char *fmt, ...)
{
    int idx = stage_index(stage);
    va_list ap;
    const char *tag = outcome == 0 ? "PASS" : (outcome == 1 ? "FAIL" : "SKIP-STRUCTURAL");
    printf("%-15s %-46s %s", tag, nn(vector_id), nn(stage));
    if (fmt != NULL && fmt[0] != '\0') {
        printf("  -- ");
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
    printf("\n");
    fflush(stdout);
    if (idx >= 0) counts[idx][outcome]++;
    if (outcome == 1) total_fail++;
}

/* Compares raw bytes against an expected hex string; prints the first differing
 * offset, both lengths and both hex values (bounded) on mismatch. */
static int cmp_hex(const char *stage, const char *vector_id, const char *what,
                   const uint8_t *got, size_t got_len, const char *expected_hex)
{
    size_t exp_len, i, first = 0;
    int differ = 0;
    char got_hex[256];
    char want_hex[256];
    size_t glen, wlen;
    if (expected_hex == NULL) {
        report(stage, vector_id, 1, "%s: expected value missing in the catalog", what);
        return 1;
    }
    exp_len = strlen(expected_hex) / 2;
    glen = got_len < 120 ? got_len : 120;
    wlen = exp_len < 120 ? exp_len : 120;

    ps4rf_hex_encode(got, glen, got_hex);
    for (i = 0; i < wlen; i += 1) {
        char b[3];
        b[0] = expected_hex[2 * i];
        b[1] = expected_hex[2 * i + 1];
        b[2] = '\0';
        want_hex[2 * i] = b[0];
        want_hex[2 * i + 1] = b[1];
    }
    want_hex[2 * wlen] = '\0';

    if (got_len != exp_len) differ = 1;
    for (i = 0; i < (got_len < exp_len ? got_len : exp_len); i++) {
        char b[3];
        unsigned v;
        b[0] = expected_hex[2 * i];
        b[1] = expected_hex[2 * i + 1];
        b[2] = '\0';
        v = (unsigned)strtoul(b, NULL, 16);
        if (v != got[i]) { differ = 1; first = i; break; }
    }
    if (!differ) return 0;
    if (got_len == exp_len) {
        report(stage, vector_id, 1,
               "%s: first differing offset %zu; expected %s (len %zu); actual %s (len %zu)",
               what, first, want_hex, exp_len, got_hex, got_len);
    } else {
        report(stage, vector_id, 1, "%s: length mismatch; expected %s (len %zu); actual %s (len %zu)",
               what, want_hex, exp_len, got_hex, got_len);
    }
    return 1;
}

static int eq_hex(const char *stage, const char *vector_id, const char *what,
                  const uint8_t *got, size_t got_len, const char *expected_hex)
{
    if (cmp_hex(stage, vector_id, what, got, got_len, expected_hex) != 0) return 1;
    return 0;
}

static int ok(const char *stage, const char *vector_id, const char *what)
{
    report(stage, vector_id, 0, "%s", what);
    return 0;
}

/* ------------------------------------------------------------------- helpers */

static char *read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    long size;
    char *buf;
    if (f == NULL) { fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno)); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    size = ftell(f);
    if (size < 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (char *)malloc((size_t)size + 1);
    if (buf == NULL) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) { free(buf); fclose(f); return NULL; }
    buf[size] = '\0';
    fclose(f);
    if (len_out != NULL) *len_out = (size_t)size;
    return buf;
}

static const jval *geto(const jval *o, const char *k)
{
    return o == NULL ? NULL : jval_get(o, k);
}

static const char *jstr(const jval *o, const char *k)
{
    const jval *v = geto(o, k);
    if (v == NULL || jval_kind(v) != JVAL_STRING) return NULL;
    return jval_string(v, NULL);
}

static int jint(const jval *o, const char *k)
{
    const jval *v = geto(o, k);
    return v == NULL ? 0 : (int)jval_int(v);
}

static uint64_t ju64(const jval *o, const char *k)
{
    const jval *v = geto(o, k);
    if (v == NULL) return 0;
    if (jval_kind(v) == JVAL_INT) return (uint64_t)jval_int(v);
    return (uint64_t)jval_double(v);
}

static int decode_hex_field(const jval *o, const char *k, uint8_t *out, size_t cap, size_t *len)
{
    const char *h = jstr(o, k);
    if (h == NULL) return -1;
    return ps4rf_hex_decode(h, out, cap, len) == PS4RF_OK ? 0 : -1;
}

/* Serializes a catalog object to JSON text (the authoritative form for the
 * transcript/keys path, which takes text like the reference implementation). */
static char *obj_text(const jval *obj)
{
    char *out = NULL;
    size_t out_len = 0;
    if (obj == NULL) return NULL;
    if (jcs_serialize(obj, &out, &out_len) != 0) return NULL;
    return out;
}

static ps4rf_direction dir_from(const char *s)
{
    if (s == NULL) return PS4RF_DIR_AGENT_TO_HOST;
    if (strcmp(s, "agent-to-host") == 0 || strcmp(s, "AGENT_TO_HOST") == 0)
        return PS4RF_DIR_AGENT_TO_HOST;
    return PS4RF_DIR_HOST_TO_AGENT;
}

/* --------------------------------------------------- shared session material */

typedef struct {
    uint8_t psk[32], agent_nonce[16], host_nonce[16];
    uint8_t k_hs[32], k_a2h[32], k_h2a[32], transcript[32];
    uint8_t pfx_a2h[4], pfx_h2a[4];
    char session_id[64];
} session_t;

static int load_session(const jval *crypto, const jval *parity, session_t *s)
{
    const jval *mat = geto(geto(crypto, "protocol"), "test_only_material");
    const jval *ps = geto(parity, "session");
    const char *sid;
    if (mat == NULL || ps == NULL || s == NULL) return -1;
    memset(s, 0, sizeof(*s));
    if (decode_hex_field(mat, "psk_hex", s->psk, 32, NULL) != 0) return -1;
    if (decode_hex_field(mat, "agent_nonce_hex", s->agent_nonce, 16, NULL) != 0) return -1;
    if (decode_hex_field(mat, "host_nonce_hex", s->host_nonce, 16, NULL) != 0) return -1;
    if (decode_hex_field(geto(ps, "keys"), "k_hs", s->k_hs, 32, NULL) != 0) return -1;
    if (decode_hex_field(geto(ps, "keys"), "k_agent_to_host", s->k_a2h, 32, NULL) != 0) return -1;
    if (decode_hex_field(geto(ps, "keys"), "k_host_to_agent", s->k_h2a, 32, NULL) != 0) return -1;
    if (decode_hex_field(ps, "transcript_sha256", s->transcript, 32, NULL) != 0) return -1;
    if (decode_hex_field(geto(ps, "nonce_prefixes"), "agent_to_host", s->pfx_a2h, 4, NULL) != 0)
        return -1;
    if (decode_hex_field(geto(ps, "nonce_prefixes"), "host_to_agent", s->pfx_h2a, 4, NULL) != 0)
        return -1;
    sid = jstr(mat, "session_id");
    if (sid == NULL) {
        const jval *pm = geto(geto(ps, "test_only_material"), "session_id");
        if (pm != NULL && jval_kind(pm) == JVAL_STRING) sid = jval_string(pm, NULL);
    }
    if (sid == NULL) return -1;
    snprintf(s->session_id, sizeof(s->session_id), "%s", sid);
    return 0;
}

/* ---------------------------------------------------- crypto catalog checks */

static int check_crypto_rfc(const jval *cat)
{
    const jval *rv = geto(cat, "rfc_vectors");
    const jval *arr;
    size_t i, n;
    int fails = 0;

    /* RFC 4231 HMAC-SHA256 */
    arr = geto(rv, "rfc4231_hmac_sha256");
    n = jval_count(arr);
    for (i = 0; i < n; i++) {
        const jval *c = jval_at(arr, i);
        uint8_t key[256], data[256], mac[32], got[32];
        size_t klen = 0, dlen = 0, mlen = 0;
        char id[64];
        snprintf(id, sizeof(id), "rfc4231_hmac_sha256#%d", jint(c, "case"));
        if (decode_hex_field(c, "key", key, sizeof(key), &klen) != 0 ||
            decode_hex_field(c, "data", data, sizeof(data), &dlen) != 0 ||
            decode_hex_field(c, "mac", mac, sizeof(mac), &mlen) != 0) {
            report("hkdf", id, 1, "vector decode error");
            fails++;
            continue;
        }
        ps4rf_hmac_sha256(key, klen, data, dlen, got);
        if (eq_hex("hkdf", id, "mac", got, 32, jstr(c, "mac")) != 0) fails++;
        else ok("hkdf", id, "mac");
    }

    /* RFC 5869 HKDF-SHA256: intermediate PRK + final OKM */
    arr = geto(rv, "rfc5869_hkdf_sha256");
    n = jval_count(arr);
    for (i = 0; i < n; i++) {
        const jval *c = jval_at(arr, i);
        uint8_t ikm[128], salt[128], info[128], prk[32], okm[128], got[128];
        size_t ikm_len = 0, salt_len = 0, info_len = 0, prk_len = 0, okm_len = 0;
        size_t l = (size_t)jint(c, "L");
        char id[64];
        snprintf(id, sizeof(id), "rfc5869_hkdf_sha256#%d", jint(c, "case"));
        if (decode_hex_field(c, "ikm", ikm, sizeof(ikm), &ikm_len) != 0 ||
            decode_hex_field(c, "salt", salt, sizeof(salt), &salt_len) != 0 ||
            decode_hex_field(c, "info", info, sizeof(info), &info_len) != 0 ||
            decode_hex_field(c, "prk", prk, sizeof(prk), &prk_len) != 0 ||
            decode_hex_field(c, "okm", okm, sizeof(okm), &okm_len) != 0) {
            report("hkdf", id, 1, "vector decode error");
            fails++;
            continue;
        }
        ps4rf_hmac_sha256(salt, salt_len, ikm, ikm_len, got); /* HKDF-Extract */
        if (eq_hex("hkdf", id, "prk", got, 32, jstr(c, "prk")) != 0) fails++;
        else if (ps4rf_hkdf_sha256(ikm, ikm_len, salt, salt_len, info, info_len, got, l) != 0) {
            report("hkdf", id, 1, "ps4rf_hkdf_sha256 returned an error");
            fails++;
        } else if (eq_hex("hkdf", id, "okm", got, l, jstr(c, "okm")) != 0) fails++;
        else ok("hkdf", id, "prk + okm");
    }

    /* RFC 8439 AEAD */
    {
        const jval *c = geto(rv, "rfc8439_aead");
        uint8_t key[32], nonce[12], aad[256], pt[256], ct[256], tag[16], out[512];
        size_t key_len = 0, nonce_len = 0, aad_len = 0, pt_len = 0, ct_len = 0, tag_len = 0;
        size_t out_len = sizeof(out);
        char expected[600];
        if (c == NULL ||
            decode_hex_field(c, "key", key, sizeof(key), &key_len) != 0 ||
            decode_hex_field(c, "nonce", nonce, sizeof(nonce), &nonce_len) != 0 ||
            decode_hex_field(c, "aad", aad, sizeof(aad), &aad_len) != 0 ||
            decode_hex_field(c, "plaintext", pt, sizeof(pt), &pt_len) != 0 ||
            decode_hex_field(c, "ciphertext", ct, sizeof(ct), &ct_len) != 0 ||
            decode_hex_field(c, "tag", tag, sizeof(tag), &tag_len) != 0) {
            report("aead", "rfc8439_aead", 1, "vector decode error");
            return fails + 1;
        }
        snprintf(expected, sizeof(expected), "%s%s", jstr(c, "ciphertext"), jstr(c, "tag"));
        if (ps4rf_aead_seal(key, nonce, aad, aad_len, pt, pt_len, out, &out_len) != 0) {
            report("aead", "rfc8439_aead", 1, "seal returned an error");
            fails++;
        } else if (eq_hex("aead", "rfc8439_aead", "ciphertext||tag", out, out_len, expected) != 0) {
            fails++;
        } else {
            size_t open_len = sizeof(out);
            if (ps4rf_aead_open(key, nonce, aad, aad_len, out, out_len, out, &open_len) != 0 ||
                open_len != pt_len || memcmp(out, pt, pt_len) != 0) {
                report("aead", "rfc8439_aead", 1, "open round trip mismatch");
                fails++;
            } else {
                ok("aead", "rfc8439_aead", "seal + open round trip");
            }
        }
    }

    /* RFC 8785 appendix B: IEEE-754 bits -> ES6 shortest representation */
    arr = geto(rv, "rfc8785_appendix_b");
    n = jval_count(arr);
    for (i = 0; i < n; i++) {
        const jval *c = jval_at(arr, i);
        const char *ieee = jstr(c, "ieee754");
        const char *expect = jstr(c, "json");
        uint8_t bits[8];
        double value = 0.0;
        char got[64];
        char id[64];
        snprintf(id, sizeof(id), "rfc8785_appendix_b[%d]", (int)i);
        if (ieee == NULL || expect == NULL || strlen(ieee) != 16 ||
            ps4rf_hex_decode(ieee, bits, sizeof(bits), NULL) != PS4RF_OK) {
            report("canonicalization", id, 1, "vector decode error");
            fails++;
            continue;
        }
        /* hex is a big-endian bit pattern: reverse into host byte order */
        {
            uint8_t le[8];
            int j;
            for (j = 0; j < 8; j++) le[j] = bits[7 - j];
            memcpy(&value, le, sizeof(value));
        }
        if (jcs_format_double(value, got, sizeof(got)) != 0) {
            report("canonicalization", id, 1, "formatter error for %s", ieee);
            fails++;
        } else if (strcmp(got, expect) != 0) {
            report("canonicalization", id, 1, "expected \"%s\"; actual \"%s\" (ieee754 %s)", expect,
                   got, ieee);
            fails++;
        } else {
            ok("canonicalization", id, got);
        }
    }

    /* RFC 8785 mixed sample (string escaping + numbers in one object) */
    {
        const jval *c = geto(rv, "rfc8785_sample");
        const char *input = jstr(c, "input_json");
        const char *expect = jstr(c, "canonical_utf8_hex");
        char *out = NULL;
        size_t out_len = 0;
        if (input == NULL || expect == NULL) {
            report("canonicalization", "rfc8785_sample", 1, "vector decode error");
            fails++;
        } else if (jcs_serialize_text(input, strlen(input), &out, &out_len) != 0) {
            report("canonicalization", "rfc8785_sample", 1, "serializer error");
            fails++;
        } else if (eq_hex("canonicalization", "rfc8785_sample", "canonical utf8", (uint8_t *)out,
                          out_len, expect) != 0) {
            fails++;
        } else {
            ok("canonicalization", "rfc8785_sample", "canonical utf8");
        }
        free(out);
    }
    return fails;
}

static int check_crypto_protocol(const jval *cat, const session_t *s)
{
    const jval *proto = geto(cat, "protocol");
    const jval *ex = geto(proto, "exchange");
    const jval *objs = geto(proto, "objects");
    int fails = 0;
    char *hello_canon = NULL, *ack_canon = NULL;
    size_t hello_len = 0, ack_len = 0;
    const char *err = NULL;
    const jval *hello_obj = geto(objs, "hello");
    const jval *ack_obj = geto(objs, "hello_ack");
    char *hello_json = obj_text(hello_obj);
    char *ack_json = obj_text(ack_obj);
    ps4rf_status st;

    if (hello_json == NULL || ack_json == NULL) {
        report("canonicalization", "protocol.objects", 1, "objects not present");
        free(hello_json);
        free(ack_json);
        return 1;
    }
    st = ps4rf_canonical_bytes_text(hello_json, strlen(hello_json), &hello_canon, &hello_len, &err);
    if (st != PS4RF_OK) {
        report("canonicalization", "protocol.objects.hello", 1, "canonicalization failed (%s)",
               err != NULL ? err : "?");
        fails++;
    } else if (eq_hex("canonicalization", "protocol.objects.hello", "canonical bytes",
                      (uint8_t *)hello_canon, hello_len, jstr(ex, "hello_canonical_hex")) != 0) {
        fails++;
    } else {
        ok("canonicalization", "protocol.objects.hello", "canonical bytes");
    }
    st = ps4rf_canonical_bytes_text(ack_json, strlen(ack_json), &ack_canon, &ack_len, &err);
    if (st != PS4RF_OK) {
        report("canonicalization", "protocol.objects.hello_ack", 1, "canonicalization failed (%s)",
               err != NULL ? err : "?");
        fails++;
    } else if (eq_hex("canonicalization", "protocol.objects.hello_ack", "canonical bytes",
                      (uint8_t *)ack_canon, ack_len, jstr(ex, "hello_ack_canonical_hex")) != 0) {
        fails++;
    } else {
        ok("canonicalization", "protocol.objects.hello_ack", "canonical bytes");
    }

    /* transcript */
    {
        uint8_t th[32];
        st = ps4rf_transcript_hash(hello_json, strlen(hello_json), ack_json, strlen(ack_json), th);
        if (st != PS4RF_OK) {
            report("transcript", "protocol.transcript_sha256", 1, "transcript failed");
            fails++;
        } else if (eq_hex("transcript", "protocol.transcript_sha256", "sha256", th, 32,
                          jstr(proto, "transcript_sha256")) != 0) {
            fails++;
        } else {
            ok("transcript", "protocol.transcript_sha256", "sha256");
        }
        if (memcmp(th, s->transcript, 32) != 0) {
            report("transcript", "session.transcript_sha256 (parity catalog)", 1,
                   "crypto and parity catalogs disagree");
            fails++;
        }
    }

    /* keys */
    {
        ps4rf_keys keys;
        char id[64];
        size_t i_field;
        struct { const char *name; const uint8_t *got; } fields[3];
        st = ps4rf_derive_keys(s->psk, s->agent_nonce, s->host_nonce, s->transcript, &keys);
        if (st != PS4RF_OK) {
            report("hkdf", "protocol.keys", 1, "derive_keys failed");
            fails++;
        } else {
            fields[0].name = "k_hs";
            fields[0].got = keys.k_hs;
            fields[1].name = "k_agent_to_host";
            fields[1].got = keys.k_agent_to_host;
            fields[2].name = "k_host_to_agent";
            fields[2].got = keys.k_host_to_agent;
            for (i_field = 0; i_field < 3; i_field++) {
                snprintf(id, sizeof(id), "protocol.keys.%s", fields[i_field].name);
                if (eq_hex("hkdf", id, "key", fields[i_field].got, 32,
                           jstr(geto(proto, "keys"), fields[i_field].name)) != 0)
                    fails++;
                else
                    ok("hkdf", id, "key");
            }
        }
    }
    return fails;
}

/* --------------------------------------------------- crypto frames + exchange */

static int check_crypto_frames(const jval *cat, const session_t *s)
{
    const jval *proto = geto(cat, "protocol");
    const jval *aad_arr = geto(proto, "aad");
    const jval *frames = geto(proto, "frames");
    const jval *ex = geto(proto, "exchange");
    int fails = 0;
    size_t i, n;

    /* AAD vectors (five enum-form entries plus one raw-value counter-example) */
    n = jval_count(aad_arr);
    for (i = 0; i < n; i++) {
        const jval *a = jval_at(aad_arr, i);
        const char *id = jstr(a, "id");
        const char *variant = jstr(a, "direction");
        ps4rf_direction dir = (id != NULL && strncmp(id, "h2a", 3) == 0) ? PS4RF_DIR_HOST_TO_AGENT
                                                                        : PS4RF_DIR_AGENT_TO_HOST;
        char *out = NULL;
        size_t out_len = 0;
        char vid[128];
        ps4rf_status st;
        if (variant != NULL && strcmp(variant, "raw-value") == 0) {
            /* The frozen form is str(direction); this vector pins the alternative. */
            snprintf(vid, sizeof(vid), "protocol.aad.%s", nn(id));
            st = ps4rf_build_aad(1, s->session_id, ju64(a, "sequence"), dir,
                                 jstr(a, "message_type"), &out, &out_len);
            if (st != PS4RF_OK) {
                report("aad", vid, 1, "build_aad failed");
                fails++;
            } else {
                char got[512];
                ps4rf_hex_encode((uint8_t *)out, out_len, got);
                if (strcmp(got, jstr(a, "aad_hex")) == 0) {
                    report("aad", vid, 1,
                           "raw-value variant equals the frozen enum form -- F1 contract broken");
                    fails++;
                } else {
                    ok("aad", vid, "differs from the frozen enum form (F1 counter-example)");
                }
            }
            free(out);
            continue;
        }
        snprintf(vid, sizeof(vid), "protocol.aad.%s", nn(id));
        st = ps4rf_build_aad(1, s->session_id, ju64(a, "sequence"), dir, jstr(a, "message_type"),
                             &out, &out_len);
        if (st != PS4RF_OK) {
            report("aad", vid, 1, "build_aad failed");
            fails++;
        } else if (eq_hex("aad", vid, "aad bytes", (uint8_t *)out, out_len, jstr(a, "aad_hex")) != 0) {
            fails++;
        } else {
            ok("aad", vid, "aad bytes");
        }
        free(out);
    }

    /* sealed frames: nonce derivation, ciphertext bytes, open round trip */
    n = jval_count(frames);
    for (i = 0; i < n; i++) {
        const jval *f = jval_at(frames, i);
        const char *id = jstr(f, "id");
        const char *mtype = jstr(f, "message_type");
        ps4rf_direction dir = dir_from(jstr(f, "direction"));
        const uint8_t *key = dir == PS4RF_DIR_HOST_TO_AGENT ? s->k_h2a : s->k_a2h;
        const uint8_t *pfx = dir == PS4RF_DIR_HOST_TO_AGENT ? s->pfx_h2a : s->pfx_a2h;
        uint64_t seq = ju64(f, "sequence");
        uint8_t pt[1024], ct[2048], nonce[12], out[2048];
        size_t pt_len = 0, ct_len = 0, out_len = 0;
        ps4rf_channel ch;
        char vid[128];
        int j;

        snprintf(vid, sizeof(vid), "protocol.frames.%s.nonce", id);
        memcpy(nonce, pfx, 4);
        for (j = 0; j < 8; j++) nonce[4 + j] = (uint8_t)((seq >> (8 * (7 - j))) & 0xffu);
        if (eq_hex("nonce", vid, "nonce", nonce, 12, jstr(f, "nonce_hex")) != 0) fails++;
        else ok("nonce", vid, "prefix || sequence");

        if (decode_hex_field(f, "plaintext_hex", pt, sizeof(pt), &pt_len) != 0 ||
            decode_hex_field(f, "ciphertext_hex", ct, sizeof(ct), &ct_len) != 0) {
            report("aead", id, 1, "frame vector decode error");
            fails++;
            continue;
        }
        snprintf(vid, sizeof(vid), "protocol.frames.%s.ciphertext", id);
        if (ps4rf_channel_init(&ch, key, pfx, s->session_id, dir, NULL, 1048576u, 1) != PS4RF_OK) {
            report("aead", vid, 1, "channel_init failed");
            fails++;
        } else {
            /* the catalog frame carries the sequence of the sealing channel */
            ch.send_seq = seq;
            out_len = sizeof(out);
            if (ps4rf_channel_seal(&ch, mtype, pt, pt_len, NULL, out, &out_len) != PS4RF_OK) {
                report("aead", vid, 1, "seal failed");
                fails++;
            } else if (eq_hex("aead", vid, "ciphertext||tag", out, out_len,
                              jstr(f, "ciphertext_hex")) != 0) {
                fails++;
            } else {
                ok("aead", vid, "ciphertext||tag");
            }
            if (out_len != ct_len) {
                report("aead", vid, 1, "ciphertext length mismatch");
                fails++;
            }
        }
        /* open round trip with a fresh receive channel */
        if (ps4rf_channel_init(&ch, key, pfx, s->session_id, dir, NULL, 1048576u, 1) == PS4RF_OK) {
            ps4rf_channel recv_ch;
            memcpy(&recv_ch, &ch, sizeof(ch));
            recv_ch.recv_seq = seq;
            out_len = sizeof(out);
            if (ps4rf_channel_open(&recv_ch, mtype, seq, ct, ct_len, out, &out_len) != PS4RF_OK) {
                report("aead", id, 1, "open failed");
                fails++;
            } else if (out_len != pt_len || memcmp(out, pt, pt_len) != 0) {
                report("aead", id, 1, "open round trip mismatch");
                fails++;
            }
        }
    }

    /* handshake exchange: four wire messages, two proofs */
    if (ex != NULL) {
        char *hello_canon = NULL, *ack_canon = NULL;
        size_t hello_len = 0, ack_len = 0;
        const char *err = NULL;
        const jval *objs = geto(proto, "objects");
        char *hello_json = obj_text(geto(objs, "hello"));
        char *ack_json = obj_text(geto(objs, "hello_ack"));
        if (hello_json == NULL || ack_json == NULL) {
            report("wire_frame", "protocol.exchange", 1, "handshake objects not present");
            free(hello_json);
            free(ack_json);
            return fails + 1;
        }
        ps4rf_canonical_bytes_text(hello_json, strlen(hello_json), &hello_canon, &hello_len, &err);
        ps4rf_canonical_bytes_text(ack_json, strlen(ack_json), &ack_canon, &ack_len, &err);

        /* helper: compare a 4-byte-length-prefixed message against agent_sent/host_sent */
        {
            size_t m;
            for (m = 0; m < 2; m++) {
                const jval *sent = geto(ex, m == 0 ? "agent_sent" : "host_sent");
                const jval *entry = jval_at(sent, 0);
                uint8_t buf[4096];
                char vid[128];
                size_t canon_len = m == 0 ? hello_len : ack_len;
                const char *canon = m == 0 ? hello_canon : ack_canon;
                if (entry == NULL || canon_len == 0 || canon_len + 4 > sizeof(buf)) continue;
                buf[0] = (uint8_t)((canon_len >> 24) & 0xffu);
                buf[1] = (uint8_t)((canon_len >> 16) & 0xffu);
                buf[2] = (uint8_t)((canon_len >> 8) & 0xffu);
                buf[3] = (uint8_t)(canon_len & 0xffu);
                memcpy(buf + 4, canon, canon_len);
                snprintf(vid, sizeof(vid), "protocol.exchange.%s_wire",
                         m == 0 ? "hello" : "hello_ack");
                if (eq_hex("wire_frame", vid, "length-prefixed canonical message", buf,
                           canon_len + 4, jstr(entry, "hex")) != 0)
                    fails++;
                else
                    ok("wire_frame", vid, "length-prefixed canonical message");
            }
        }

        /* AUTH and AUTH_ACK messages rebuilt from the pinned proofs */
        {
            ps4rf_keys keys;
            uint8_t mac[32];
            char mac_hex[65];
            jval *msg;
            char *canon = NULL;
            size_t canon_len = 0;
            uint8_t buf[4096];
            const jval *entry;
            if (ps4rf_derive_keys(s->psk, s->agent_nonce, s->host_nonce, s->transcript, &keys) ==
                PS4RF_OK) {
                ps4rf_proof(keys.k_hs, "agent", s->transcript, mac);
                if (eq_hex("hkdf", "protocol.exchange.auth_mac", "proof(k_hs, agent)",
                           mac, 32, jstr(ex, "auth_mac_hex")) != 0) fails++;
                else ok("hkdf", "protocol.exchange.auth_mac", "proof(k_hs, agent)");
                ps4rf_hex_encode(mac, 32, mac_hex);
                msg = jval_new_object();
                jval_obj_set(msg, "mac", jval_new_string(mac_hex));
                jval_obj_set(msg, "msg", jval_new_string("AUTH"));
                if (ps4rf_canonical_bytes(msg, &canon, &canon_len, &err) == PS4RF_OK &&
                    canon_len + 4 <= sizeof(buf)) {
                    buf[0] = (uint8_t)((canon_len >> 24) & 0xffu);
                    buf[1] = (uint8_t)((canon_len >> 16) & 0xffu);
                    buf[2] = (uint8_t)((canon_len >> 8) & 0xffu);
                    buf[3] = (uint8_t)(canon_len & 0xffu);
                    memcpy(buf + 4, canon, canon_len);
                    entry = jval_at(geto(ex, "agent_sent"), 1);
                    if (eq_hex("wire_frame", "protocol.exchange.auth_wire", "AUTH message", buf,
                               canon_len + 4, jstr(entry, "hex")) != 0)
                        fails++;
                    else
                        ok("wire_frame", "protocol.exchange.auth_wire", "AUTH message");
                } else {
                    report("wire_frame", "protocol.exchange.auth_wire", 1, "canonicalization failed");
                    fails++;
                }
                free(canon);
                jval_free(msg);

                ps4rf_proof(keys.k_hs, "host", s->transcript, mac);
                if (eq_hex("hkdf", "protocol.exchange.auth_ack_mac", "proof(k_hs, host)", mac, 32,
                           jstr(ex, "auth_ack_mac_hex")) != 0) fails++;
                else ok("hkdf", "protocol.exchange.auth_ack_mac", "proof(k_hs, host)");
                ps4rf_hex_encode(mac, 32, mac_hex);
                msg = jval_new_object();
                jval_obj_set(msg, "mac", jval_new_string(mac_hex));
                jval_obj_set(msg, "msg", jval_new_string("AUTH_ACK"));
                canon = NULL;
                canon_len = 0;
                if (ps4rf_canonical_bytes(msg, &canon, &canon_len, &err) == PS4RF_OK &&
                    canon_len + 4 <= sizeof(buf)) {
                    buf[0] = (uint8_t)((canon_len >> 24) & 0xffu);
                    buf[1] = (uint8_t)((canon_len >> 16) & 0xffu);
                    buf[2] = (uint8_t)((canon_len >> 8) & 0xffu);
                    buf[3] = (uint8_t)(canon_len & 0xffu);
                    memcpy(buf + 4, canon, canon_len);
                    entry = jval_at(geto(ex, "host_sent"), 1);
                    if (eq_hex("wire_frame", "protocol.exchange.auth_ack_wire",
                               "AUTH_ACK message", buf, canon_len + 4, jstr(entry, "hex")) != 0)
                        fails++;
                    else
                        ok("wire_frame", "protocol.exchange.auth_ack_wire", "AUTH_ACK message");
                } else {
                    report("wire_frame", "protocol.exchange.auth_ack_wire", 1,
                           "canonicalization failed");
                    fails++;
                }
                free(canon);
                jval_free(msg);
            }
        }
        free(hello_canon);
        free(ack_canon);
        free(hello_json);
        free(ack_json);
    }
    return fails;
}

/* ------------------------------------------------------------ parity catalog */

static int check_parity(const jval *par, const jval *crypto, const session_t *s)
{
    const jval *frames = geto(par, "frames");
    const jval *wf = geto(par, "wire_frame");
    const jval *fsm = geto(par, "direction_fsm");
    int fails = 0;
    size_t i, n;
    (void)crypto;

    /* session material cross-check: the parity catalog must agree with the crypto catalog */
    {
        ps4rf_keys keys;
        uint8_t pfx[4];
        if (ps4rf_derive_keys(s->psk, s->agent_nonce, s->host_nonce, s->transcript, &keys) !=
            PS4RF_OK) {
            report("hkdf", "parity.session.keys", 1, "derive_keys failed");
            fails++;
        } else if (eq_hex("hkdf", "parity.session.keys.k_hs", "k_hs", keys.k_hs, 32,
                          jstr(geto(geto(par, "session"), "keys"), "k_hs")) != 0 ||
                   eq_hex("hkdf", "parity.session.keys.k_agent_to_host", "k_agent_to_host",
                          keys.k_agent_to_host, 32,
                          jstr(geto(geto(par, "session"), "keys"), "k_agent_to_host")) != 0 ||
                   eq_hex("hkdf", "parity.session.keys.k_host_to_agent", "k_host_to_agent",
                          keys.k_host_to_agent, 32,
                          jstr(geto(geto(par, "session"), "keys"), "k_host_to_agent")) != 0) {
            fails++;
        } else {
            ok("hkdf", "parity.session.keys", "three directional keys");
        }
        if (ps4rf_nonce_prefix(s->psk, s->agent_nonce, s->host_nonce, s->transcript,
                               PS4RF_DIR_AGENT_TO_HOST, pfx) != PS4RF_OK ||
            eq_hex("hkdf", "parity.session.nonce_prefixes.agent_to_host", "prefix", pfx, 4,
                   jstr(geto(geto(par, "session"), "nonce_prefixes"), "agent_to_host")) != 0) {
            fails++;
        } else if (ps4rf_nonce_prefix(s->psk, s->agent_nonce, s->host_nonce, s->transcript,
                                      PS4RF_DIR_HOST_TO_AGENT, pfx) != PS4RF_OK ||
                   eq_hex("hkdf", "parity.session.nonce_prefixes.host_to_agent", "prefix", pfx, 4,
                          jstr(geto(geto(par, "session"), "nonce_prefixes"),
                               "host_to_agent")) != 0) {
            fails++;
        } else {
            ok("hkdf", "parity.session.nonce_prefixes", "both direction prefixes");
        }
    }

    /* session frames: canonical bytes, nonce, ciphertext, header, full wire frame */
    n = jval_count(frames);
    for (i = 0; i < n; i++) {
        const jval *f = jval_at(frames, i);
        const char *id = jstr(f, "id");
        const char *mtype = jstr(f, "message_type");
        ps4rf_direction dir = dir_from(jstr(f, "direction"));
        const uint8_t *key = dir == PS4RF_DIR_HOST_TO_AGENT ? s->k_h2a : s->k_a2h;
        const uint8_t *pfx = dir == PS4RF_DIR_HOST_TO_AGENT ? s->pfx_h2a : s->pfx_a2h;
        uint64_t seq = ju64(f, "sequence");
        const jval *obj = geto(f, "object");
        char vid[160];
        ps4rf_channel ch, recv_ch;
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        char *canon = NULL;
        size_t canon_len = 0;
        const char *err = NULL;
        int j;

        snprintf(vid, sizeof(vid), "parity.frames.%s.canonical", nn(id));
        if (obj != NULL && ps4rf_canonical_bytes(obj, &canon, &canon_len, &err) == PS4RF_OK) {
            if (eq_hex("canonicalization", vid, "canonical bytes", (uint8_t *)canon, canon_len,
                       jstr(f, "canonical_hex")) != 0)
                fails++;
            else
                ok("canonicalization", vid, "canonical bytes");
        } else {
            report("canonicalization", vid, 1, "canonicalization failed");
            fails++;
        }

        snprintf(vid, sizeof(vid), "parity.frames.%s.nonce", nn(id));
        {
            uint8_t nonce[12];
            memcpy(nonce, pfx, 4);
            for (j = 0; j < 8; j++) nonce[4 + j] = (uint8_t)((seq >> (8 * (7 - j))) & 0xffu);
            if (eq_hex("nonce", vid, "nonce", nonce, 12, jstr(f, "nonce_hex")) != 0) fails++;
            else ok("nonce", vid, "prefix || sequence");
        }

        snprintf(vid, sizeof(vid), "parity.frames.%s.wire", nn(id));
        if (canon == NULL ||
            ps4rf_channel_init(&ch, key, pfx, s->session_id, dir, NULL, 1048576u, 1) != PS4RF_OK) {
            report("wire_frame", vid, 1, "setup failed");
            fails++;
            free(canon);
            continue;
        }
        ch.send_seq = seq; /* the catalog frame carries the sealing sequence */
        if (ps4rf_frame_encode(&ch, mtype, (uint8_t *)canon, canon_len, &wire, &wire_len, 0) !=
            PS4RF_OK) {
            report("wire_frame", vid, 1, "encode failed");
            fails++;
        } else if (eq_hex("wire_frame", vid, "header || ciphertext", wire, wire_len,
                          jstr(f, "wire_hex")) != 0) {
            fails++;
        } else {
            ok("wire_frame", vid, "header || ciphertext");
        }
        /* header and frame length sub-checks */
        snprintf(vid, sizeof(vid), "parity.frames.%s.header", id);
        if (wire_len >= PS4RF_FRAME_HEADER_BYTES &&
            eq_hex("frame_header", vid, "13-byte header", wire, PS4RF_FRAME_HEADER_BYTES,
                   jstr(f, "header_hex")) != 0) {
            fails++;
        } else if (wire_len >= PS4RF_FRAME_HEADER_BYTES) {
            ok("frame_header", vid, "13-byte header");
        }
        if (wire_len >= PS4RF_FRAME_HEADER_BYTES &&
            (int)jval_int(geto(f, "frame_type_byte")) != (int)wire[4]) {
            report("frame_header", id, 1, "type byte mismatch in the catalog itself");
            fails++;
        }
        /* decode round trip */
        if (ps4rf_channel_init(&recv_ch, key, pfx, s->session_id, dir, NULL, 1048576u, 1) ==
            PS4RF_OK) {
            char mtype_out[16];
            uint64_t seq_out = 0;
            uint8_t *pt_out = NULL;
            size_t pt_len_out = 0;
            recv_ch.recv_seq = seq;
            snprintf(vid, sizeof(vid), "parity.frames.%s.decode", id);
            if (ps4rf_frame_decode(&recv_ch, wire, wire_len, mtype_out, &seq_out, &pt_out,
                                   &pt_len_out) != PS4RF_OK) {
                report("wire_frame", vid, 1, "decode failed");
                fails++;
            } else if (strcmp(mtype_out, mtype) != 0 || seq_out != seq ||
                       eq_hex("wire_frame", vid, "plaintext", pt_out, pt_len_out,
                              jstr(f, "canonical_hex")) != 0) {
                fails++;
            } else {
                ok("wire_frame", vid, "decode round trip");
            }
            free(pt_out);
        }
        free(wire);
        free(canon);
    }

    /* wire mapping v1 table */
    if (wf != NULL) {
        const jval *table = geto(wf, "type_table");
        char vid[128];
        for (i = 0; i < jval_count(table); i++) {
            const char *key = jval_key_at(table, i);
            const char *name = jval_string(jval_at(table, i), NULL);
            unsigned byte = (unsigned)strtoul(key, NULL, 0);
            snprintf(vid, sizeof(vid), "parity.wire_frame.type_table[%s]", key);
            if (byte < 1 || byte > 5 || name == NULL) {
                report("frame_header", vid, 1, "malformed table entry");
                fails++;
            } else if (ps4rf_frame_type_byte(name) != (int)byte ||
                       (ps4rf_frame_type_name((uint8_t)byte) == NULL ||
                        strcmp(ps4rf_frame_type_name((uint8_t)byte), name) != 0)) {
                report("frame_header", vid, 1, "mapping mismatch: %s", name);
                fails++;
            } else {
                ok("frame_header", vid, name);
            }
        }
        /* reserved semantics: never sent unless explicitly allowed */
        {
            uint8_t header[PS4RF_FRAME_HEADER_BYTES];
            ps4rf_status st;
            st = ps4rf_frame_build_header(16, "EVENT", 0, 0, header);
            if (st != PS4RF_ERR_RESERVED_TYPE) {
                report("frame_header", "parity.wire_frame.reserved_event", 1,
                       "EVENT without allow_reserved returned %s", ps4rf_status_name(st));
                fails++;
            } else {
                ok("frame_header", "parity.wire_frame.reserved_event", "ReservedFrameType");
            }
            st = ps4rf_frame_build_header(16, "READY", 0, 0, header);
            if (st != PS4RF_ERR_RESERVED_TYPE) {
                report("frame_header", "parity.wire_frame.reserved_ready", 1,
                       "READY without allow_reserved returned %s", ps4rf_status_name(st));
                fails++;
            } else {
                ok("frame_header", "parity.wire_frame.reserved_ready", "ReservedFrameType");
            }
        }
        /* unknown type byte */
        {
            uint8_t raw[PS4RF_FRAME_HEADER_BYTES] = {0, 0, 0, 0, 0x07, 0, 0, 0, 0, 0, 0, 0, 0};
            char mtype[16];
            uint64_t seq = 0;
            uint32_t len = 0;
            if (ps4rf_frame_parse_header(raw, 1048576u, mtype, &seq, &len) != PS4RF_ERR_UNKNOWN_TYPE) {
                report("frame_header", "parity.wire_frame.unknown_type_byte", 1, "0x07 accepted");
                fails++;
            } else {
                ok("frame_header", "parity.wire_frame.unknown_type_byte", "UnknownFrameType");
            }
        }
        /* length check before allocation */
        {
            uint8_t raw[PS4RF_FRAME_HEADER_BYTES] = {0x00, 0x10, 0x00, 0x00, 0x01,
                                                     0,    0,    0,    0,    0, 0, 0, 0};
            char mtype[16];
            uint64_t seq = 0;
            uint32_t len = 0;
            if (ps4rf_frame_parse_header(raw, 1024u, mtype, &seq, &len) != PS4RF_ERR_FRAME_LIMIT) {
                report("frame_header", "parity.wire_frame.length_check", 1, "oversize length accepted");
                fails++;
            } else {
                ok("frame_header", "parity.wire_frame.length_check", "FrameLimitExceeded");
            }
        }
        /* sequence ceiling in the header */
        {
            uint8_t raw[PS4RF_FRAME_HEADER_BYTES] = {0, 0, 0, 16, 0x01,
                                                     0x00, 0x20, 0, 0, 0, 0, 0, 0};
            char mtype[16];
            uint64_t seq = 0;
            uint32_t len = 0;
            if (ps4rf_frame_parse_header(raw, 1048576u, mtype, &seq, &len) !=
                PS4RF_ERR_SEQ_EXHAUSTED) {
                report("frame_header", "parity.wire_frame.sequence_ceiling", 1,
                       "sequence 2**53 accepted");
                fails++;
            } else {
                ok("frame_header", "parity.wire_frame.sequence_ceiling", "SequenceExhausted");
            }
        }
        /* active types for W2 */
        {
            const jval *active = geto(wf, "active_types_w2");
            for (i = 0; i < jval_count(active); i++) {
                const char *name = jval_string(jval_at(active, i), NULL);
                char vid[128];
                snprintf(vid, sizeof(vid), "parity.wire_frame.active[%d]", (int)i);
                if (name == NULL || ps4rf_frame_type_is_reserved(name) ||
                    ps4rf_frame_type_byte(name) < 0) {
                    report("frame_header", vid, 1, "active type is unknown or reserved");
                    fails++;
                } else {
                    ok("frame_header", vid, name);
                }
            }
        }
    }

    /* direction FSM (F16) */
    if (fsm != NULL) {
        int expect_host_wrong = 0, expect_agent_wrong = 0;
        const char *inbound_agent = jstr(fsm, "host_to_agent");
        const char *inbound_host = jstr(fsm, "agent_to_host");
        (void)inbound_agent;
        (void)inbound_host;
        if (ps4rf_direction_check(PS4RF_DIR_AGENT_TO_HOST, "REQUEST") != PS4RF_OK) {
            report("wire_frame", "parity.direction_fsm.agent_inbound_request", 1,
                   "agent rejected an inbound REQUEST");
            fails++;
        } else {
            ok("wire_frame", "parity.direction_fsm.agent_inbound_request", "accepted");
        }
        if (ps4rf_direction_check(PS4RF_DIR_AGENT_TO_HOST, "RESPONSE") != PS4RF_ERR_PROTOCOL) {
            report("wire_frame", "parity.direction_fsm.agent_inbound_response", 1,
                   "agent accepted an inbound RESPONSE");
            fails++;
        } else {
            ok("wire_frame", "parity.direction_fsm.agent_inbound_response", "ProtocolError");
        }
        expect_host_wrong = ps4rf_direction_check(PS4RF_DIR_HOST_TO_AGENT, "REQUEST");
        if (expect_host_wrong != PS4RF_ERR_PROTOCOL) {
            report("wire_frame", "parity.direction_fsm.host_inbound_request", 1,
                   "host accepted an inbound REQUEST");
            fails++;
        } else {
            ok("wire_frame", "parity.direction_fsm.host_inbound_request", "ProtocolError");
        }
        expect_agent_wrong = ps4rf_direction_check(PS4RF_DIR_HOST_TO_AGENT, "BYE");
        if (expect_agent_wrong != PS4RF_OK) {
            report("wire_frame", "parity.direction_fsm.host_inbound_bye", 1, "host rejected BYE");
            fails++;
        } else {
            ok("wire_frame", "parity.direction_fsm.host_inbound_bye", "accepted");
        }
    }

    /* channel cases: one positive round trip plus the four fail-close cases */
    {
        ps4rf_channel a, b;
        uint8_t ct[512], pt_out[512];
        size_t ct_len = sizeof(ct), pt_len = sizeof(pt_out);
        uint64_t seq = 0;
        const char *probe = "{\"probe\":\"channel-open\"}";
        if (ps4rf_channel_init(&a, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK &&
            ps4rf_channel_init(&b, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK &&
            ps4rf_channel_seal(&a, "RESPONSE", (const uint8_t *)probe, strlen(probe), &seq, ct,
                               &ct_len) == PS4RF_OK &&
            ps4rf_channel_open(&b, "RESPONSE", seq, ct, ct_len, pt_out, &pt_len) == PS4RF_OK &&
            pt_len == strlen(probe) && memcmp(pt_out, probe, pt_len) == 0) {
            ok("aead", "parity.channel.open_roundtrip", "seal + open");
        } else {
            report("aead", "parity.channel.open_roundtrip", 1, "round trip failed");
            fails++;
        }

        /* wrong message type -> AuthenticationFailed */
        if (ps4rf_channel_init(&a, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK &&
            ps4rf_channel_init(&b, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK) {
            ct_len = sizeof(ct);
            pt_len = sizeof(pt_out);
            ps4rf_channel_seal(&a, "RESPONSE", (const uint8_t *)probe, strlen(probe), &seq, ct,
                               &ct_len);
            if (ps4rf_channel_open(&b, "BYE", seq, ct, ct_len, pt_out, &pt_len) !=
                PS4RF_ERR_AUTH_FAILED) {
                report("aead", "parity.channel.open_wrong_message_type_rejected", 1,
                       "wrong message type was accepted");
                fails++;
            } else {
                ok("aead", "parity.channel.open_wrong_message_type_rejected", "AuthenticationFailed");
            }
        }
        /* sequence gap and replay -> ReplayDetected */
        if (ps4rf_channel_init(&a, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK &&
            ps4rf_channel_init(&b, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK) {
            uint64_t s0 = 0, s1 = 0;
            uint8_t ct0[512], ct1[512];
            size_t ct0_len = sizeof(ct0), ct1_len = sizeof(ct1);
            ps4rf_channel_seal(&a, "RESPONSE", (const uint8_t *)probe, strlen(probe), &s0, ct0,
                               &ct0_len);
            ps4rf_channel_seal(&a, "RESPONSE", (const uint8_t *)probe, strlen(probe), &s1, ct1,
                               &ct1_len);
            (void)s1;
            pt_len = sizeof(pt_out);
            if (ps4rf_channel_open(&b, "RESPONSE", 1, ct1, ct1_len, pt_out, &pt_len) !=
                PS4RF_ERR_REPLAY) {
                report("aead", "parity.channel.open_sequence_gap_rejected", 1, "gap accepted");
                fails++;
            } else {
                ok("aead", "parity.channel.open_sequence_gap_rejected", "ReplayDetected");
            }
            pt_len = sizeof(pt_out);
            if (ps4rf_channel_open(&b, "RESPONSE", 0, ct0, ct0_len, pt_out, &pt_len) != PS4RF_OK) {
                report("aead", "parity.channel.open_sequence_gap_rejected", 1,
                       "sequence 0 did not open afterwards");
                fails++;
            }
            pt_len = sizeof(pt_out);
            if (ps4rf_channel_open(&b, "RESPONSE", 0, ct0, ct0_len, pt_out, &pt_len) !=
                PS4RF_ERR_REPLAY) {
                report("aead", "parity.channel.open_replay_rejected", 1, "replay accepted");
                fails++;
            } else {
                ok("aead", "parity.channel.open_replay_rejected", "ReplayDetected");
            }
        }
        /* cross direction -> AuthenticationFailed */
        if (ps4rf_channel_init(&a, s->k_a2h, s->pfx_a2h, s->session_id, PS4RF_DIR_AGENT_TO_HOST, NULL,
                               1024u, 1) == PS4RF_OK &&
            ps4rf_channel_init(&b, s->k_h2a, s->pfx_h2a, s->session_id, PS4RF_DIR_HOST_TO_AGENT, NULL,
                               1024u, 1) == PS4RF_OK) {
            ct_len = sizeof(ct);
            pt_len = sizeof(pt_out);
            ps4rf_channel_seal(&a, "RESPONSE", (const uint8_t *)probe, strlen(probe), &seq, ct,
                               &ct_len);
            if (ps4rf_channel_open(&b, "RESPONSE", seq, ct, ct_len, pt_out, &pt_len) !=
                PS4RF_ERR_AUTH_FAILED) {
                report("aead", "parity.channel.cross_direction_open_rejected", 1,
                       "cross-direction frame was accepted");
                fails++;
            } else {
                ok("aead", "parity.channel.cross_direction_open_rejected", "AuthenticationFailed");
            }
        }
    }
    return fails;
}

/* ------------------------------------------------- script interpreter (W2-D) */

/* Machine-readable boundary/negative vectors from tests/fixtures/parity/
 * gen_negative.py. Every expectation in that catalog was recomputed from the
 * frozen Python core, so a PASS means the native side matched the reference. */

typedef struct {
    ps4rf_channel ch;
    int has_ch;
    uint64_t last_seq;
    uint8_t last_ct[8192];
    size_t last_ct_len;
    ps4rf_keys keys;
    int has_keys;
    uint8_t transcript[32];
    int has_th;
} script_ctx;

/* The reference boundary cases canonicalize a one-element list holding the
 * number (e.g. [4.5] -> "4.5"), so the native side builds the same shape. */
static jval *make_double_value(const char *kind)
{
    const char *text = NULL;
    jval *value;
    jval *arr;
    if (kind == NULL) return NULL;
    if (strcmp(kind, "nan") == 0) text = "NaN";
    else if (strcmp(kind, "inf") == 0) text = "Infinity";
    else if (strcmp(kind, "-inf") == 0) text = "-Infinity";
    else if (strcmp(kind, "neg_zero") == 0) text = "-0.0";
    else if (strcmp(kind, "4.5") == 0) text = "4.5";
    else if (strcmp(kind, "1e30") == 0) text = "1e30";
    if (text == NULL) return NULL;
    value = jval_parse(text, strlen(text));
    if (value == NULL) return NULL;
    arr = jval_new_array();
    if (arr == NULL) {
        jval_free(value);
        return NULL;
    }
    if (jval_arr_add(arr, value) != 0) {
        jval_free(value);
        jval_free(arr);
        return NULL;
    }
    return arr;
}

static int expect_status(const char *case_id, const char *stage, ps4rf_status status,
                         const jval *step)
{
    const char *expect = jstr(step, "expect");
    const char *wanted = jstr(step, "exception");
    if (expect == NULL) return 0;
    if (strcmp(expect, "ok") == 0) {
        if (status != PS4RF_OK) {
            report(stage, case_id, 1, "expected ok; got %s", ps4rf_status_name(status));
            return 1;
        }
        return 0;
    }
    if (strcmp(expect, "raises") == 0) {
        if (status == PS4RF_OK) {
            report(stage, case_id, 1, "expected %s; the call succeeded",
                   wanted != NULL ? wanted : "?");
            return 1;
        }
        if (wanted != NULL && strcmp(ps4rf_status_name(status), wanted) != 0) {
            report(stage, case_id, 1, "expected %s; got %s", wanted, ps4rf_status_name(status));
            return 1;
        }
        return 0;
    }
    report(stage, case_id, 1, "unknown expectation %s", expect);
    return 1;
}

/* ------------------------------------------------------ handshake counterpart */

typedef struct {
    int fd;
    uint8_t psk[32];
    uint8_t agent_nonce[16];
    uint8_t host_nonce[16];
    jval *hello;
    jval *ack;
    const char *role;        /* role of the MAIN thread */
    const char *counterpart; /* catalog | rogue_auth_mac | rogue_transcript | rogue_ack_mac */
    const char *hello_json;
    const char *ack_mutated_json;
    ps4rf_status status;
    ps4rf_keys keys;
    int keys_valid;
} hs_ctx;

static void *hs_counterpart_thread(void *arg)
{
    hs_ctx *c = (hs_ctx *)arg;
    if (strcmp(c->counterpart, "catalog") == 0) {
        if (strcmp(c->role, "agent") == 0) {
            c->status = ps4rf_host_handshake(c->fd, c->psk, c->ack, &c->keys, NULL);
            c->keys_valid = c->status == PS4RF_OK;
        } else {
            c->status = ps4rf_agent_handshake(c->fd, c->psk, c->hello, &c->keys, NULL);
            c->keys_valid = c->status == PS4RF_OK;
        }
    } else if (strcmp(c->counterpart, "rogue_ack_mac") == 0) {
        jval *hello = NULL, *auth = NULL, *ack_msg;
        char zero_hex[65];
        memset(zero_hex, '0', 64);
        zero_hex[64] = '\0';
        c->status = ps4rf_hs_recv(c->fd, &hello);
        if (c->status == PS4RF_OK) c->status = ps4rf_hs_send(c->fd, c->ack);
        if (c->status == PS4RF_OK) c->status = ps4rf_hs_recv(c->fd, &auth);
        if (c->status == PS4RF_OK) {
            ack_msg = jval_new_object();
            jval_obj_set(ack_msg, "mac", jval_new_string(zero_hex));
            jval_obj_set(ack_msg, "msg", jval_new_string("AUTH_ACK"));
            c->status = ps4rf_hs_send(c->fd, ack_msg);
            jval_free(ack_msg);
        }
        jval_free(hello);
        jval_free(auth);
    } else if (strcmp(c->counterpart, "rogue_auth_mac") == 0) {
        jval *ack_recv = NULL, *auth;
        char zero_hex[65];
        memset(zero_hex, '0', 64);
        zero_hex[64] = '\0';
        c->status = ps4rf_hs_send(c->fd, c->hello);
        if (c->status == PS4RF_OK) c->status = ps4rf_hs_recv(c->fd, &ack_recv);
        if (c->status == PS4RF_OK) {
            auth = jval_new_object();
            jval_obj_set(auth, "mac", jval_new_string(zero_hex));
            jval_obj_set(auth, "msg", jval_new_string("AUTH"));
            c->status = ps4rf_hs_send(c->fd, auth);
            jval_free(auth);
        }
        jval_free(ack_recv);
    } else if (strcmp(c->counterpart, "rogue_ack_object") == 0) {
        /* sends the caller-provided HELLO_ACK verbatim (used for malformed ACK cases) */
        jval *hello = NULL;
        uint8_t byte;
        c->status = ps4rf_hs_recv(c->fd, &hello);
        if (c->status == PS4RF_OK) c->status = ps4rf_hs_send(c->fd, c->ack);
        /* drain one byte so a non-failing counterpart still terminates */
        (void)!read(c->fd, &byte, 1);
        jval_free(hello);
    } else if (strcmp(c->counterpart, "rogue_transcript") == 0) {
        jval *ack_recv = NULL, *auth;
        uint8_t th[32], mac[32];
        ps4rf_keys keys;
        char mac_hex[65];
        c->status = ps4rf_hs_send(c->fd, c->hello);
        if (c->status == PS4RF_OK) c->status = ps4rf_hs_recv(c->fd, &ack_recv);
        if (c->status == PS4RF_OK) {
            /* transcript over a mutated ACK: the host must reject the proof */
            c->status = ps4rf_transcript_hash(c->hello_json, strlen(c->hello_json),
                                             c->ack_mutated_json,
                                             strlen(c->ack_mutated_json), th);
        }
        if (c->status == PS4RF_OK)
            c->status = ps4rf_derive_keys(c->psk, c->agent_nonce, c->host_nonce, th, &keys);
        if (c->status == PS4RF_OK) {
            ps4rf_proof(keys.k_hs, "agent", th, mac);
            ps4rf_hex_encode(mac, 32, mac_hex);
            auth = jval_new_object();
            jval_obj_set(auth, "mac", jval_new_string(mac_hex));
            jval_obj_set(auth, "msg", jval_new_string("AUTH"));
            c->status = ps4rf_hs_send(c->fd, auth);
            jval_free(auth);
        }
        jval_free(ack_recv);
    } else {
        c->status = PS4RF_ERR_PROTOCOL;
    }
    close(c->fd);
    return NULL;
}

/* -------------------------------------------------------------- step runner */

static int run_step(script_ctx *ctx, const jval *step, const char *case_id, const session_t *s)
{
    const char *call = jstr(step, "call");
    const char *stage = jstr(step, "stage");
    const char *expect = jstr(step, "expect");
    char vid[192];
    int fails = 0;

    if (call == NULL || stage == NULL) {
        report("canonicalization", case_id, 1, "malformed step (call/stage missing)");
        return 1;
    }
    {
        int wrote = snprintf(vid, sizeof(vid), "%.*s/%.*s", (int)(sizeof(vid) / 2 - 1),
                             nn(case_id), (int)(sizeof(vid) / 2 - 1), nn(call));
        if (wrote < 0 || (size_t)wrote >= sizeof(vid)) {
            report("canonicalization", case_id, 1, "vector id overflow");
            return 1;
        }
    }

    if (strcmp(call, "skip_structural") == 0) {
        report(stage, vid, 2, "%s", jstr(step, "reason") != NULL ? jstr(step, "reason") : "structural");
        return 0;
    }

    if (strcmp(call, "canon_text") == 0) {
        const char *json = jstr(step, "json");
        char *out = NULL;
        size_t out_len = 0;
        const char *err_name = NULL;
        int rc = ps4rf_canonical_bytes_text(json, strlen(json), &out, &out_len, &err_name);
        ps4rf_status st = rc == 0 ? PS4RF_OK : ps4rf_status_from_error_name(err_name);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "canonical bytes", (uint8_t *)out, out_len,
                            jstr(step, "expect_hex"));
        free(out);
        return fails;
    }

    if (strcmp(call, "canon_double") == 0) {
        jval *v = make_double_value(jstr(step, "kind"));
        char *out = NULL;
        size_t out_len = 0;
        const char *err_name = NULL;
        ps4rf_status st;
        if (v == NULL) {
            report(stage, vid, 1, "unknown double kind %s", nn(jstr(step, "kind")));
            return 1;
        }
        st = ps4rf_canonical_bytes(v, &out, &out_len, &err_name) == 0
                 ? PS4RF_OK
                 : ps4rf_status_from_error_name(err_name);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "canonical bytes", (uint8_t *)out, out_len,
                            jstr(step, "expect_hex"));
        free(out);
        jval_free(v);
        return fails;
    }

    if (strcmp(call, "chan_init") == 0) {
        uint8_t key[32], pfx[4];
        size_t klen = 0, plen = 0;
        const char *sid = jstr(step, "session_id");
        ps4rf_status st;
        if (decode_hex_field(step, "key_hex", key, sizeof(key), &klen) != 0 || klen != 32 ||
            decode_hex_field(step, "prefix_hex", pfx, sizeof(pfx), &plen) != 0 || plen != 4) {
            report(stage, vid, 1, "script key/prefix hex must be 32/4 bytes");
            return 1;
        }
        st = ps4rf_channel_init(&ctx->ch, key, pfx, sid != NULL ? sid : s->session_id,
                                dir_from(jstr(step, "direction")), jstr(step, "suite"),
                                (size_t)jint(step, "max_frame_bytes"),
                                (uint32_t)jint(step, "protocol_version"));
        ctx->has_ch = st == PS4RF_OK;
        fails += expect_status(vid, stage, st, step);
        return fails;
    }

    if (strcmp(call, "set_seq") == 0) {
        if (!ctx->has_ch) {
            report(stage, vid, 1, "set_seq without a channel");
            return 1;
        }
        if (geto(step, "send") != NULL) ctx->ch.send_seq = ju64(step, "send");
        if (geto(step, "recv") != NULL) ctx->ch.recv_seq = ju64(step, "recv");
        return 0;
    }

    if (strcmp(call, "seal") == 0) {
        uint8_t pt[4096], ct[8192];
        size_t pt_len = 0, ct_len = sizeof(ct);
        uint64_t seq = 0;
        ps4rf_status st;
        if (!ctx->has_ch) {
            report(stage, vid, 1, "seal without a channel");
            return 1;
        }
        if (decode_hex_field(step, "pt_hex", pt, sizeof(pt), &pt_len) != 0) {
            report(stage, vid, 1, "bad plaintext hex");
            return 1;
        }
        st = ps4rf_channel_seal(&ctx->ch, jstr(step, "mtype"), pt, pt_len, &seq, ct, &ct_len);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK) {
            if (expect != NULL && strcmp(expect, "ok") == 0 && jstr(step, "expect_hex") != NULL)
                fails += eq_hex(stage, vid, "ciphertext||tag", ct, ct_len, jstr(step, "expect_hex"));
            if (geto(step, "expect_seq") != NULL && seq != ju64(step, "expect_seq")) {
                report(stage, vid, 1, "expected sequence %llu; got %llu",
                       (unsigned long long)ju64(step, "expect_seq"), (unsigned long long)seq);
                fails++;
            }
            ctx->last_seq = seq;
            if (ct_len <= sizeof(ctx->last_ct)) {
                memcpy(ctx->last_ct, ct, ct_len);
                ctx->last_ct_len = ct_len;
            }
        }
        return fails;
    }

    if (strcmp(call, "open") == 0) {
        uint8_t ct[8192], pt[8192];
        size_t ct_len = 0, pt_len = sizeof(pt);
        uint64_t seq;
        ps4rf_status st;
        const char *ct_hex = jstr(step, "ct_hex");
        if (!ctx->has_ch) {
            report(stage, vid, 1, "open without a channel");
            return 1;
        }
        if (ct_hex != NULL) {
            if (ps4rf_hex_decode(ct_hex, ct, sizeof(ct), &ct_len) != PS4RF_OK) {
                report(stage, vid, 1, "bad ciphertext hex");
                return 1;
            }
        } else {
            if (ctx->last_ct_len == 0) {
                report(stage, vid, 1, "no previous ciphertext to reuse");
                return 1;
            }
            memcpy(ct, ctx->last_ct, ctx->last_ct_len);
            ct_len = ctx->last_ct_len;
        }
        seq = geto(step, "seq") != NULL ? ju64(step, "seq") : ctx->last_seq;
        st = ps4rf_channel_open(&ctx->ch, jstr(step, "mtype"), seq, ct, ct_len, pt, &pt_len);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0 &&
            jstr(step, "expect_hex") != NULL)
            fails += eq_hex(stage, vid, "plaintext", pt, pt_len, jstr(step, "expect_hex"));
        return fails;
    }

    if (strcmp(call, "aad") == 0) {
        char *out = NULL;
        size_t out_len = 0;
        const char *sid = jstr(step, "session_id");
        ps4rf_status st = ps4rf_build_aad((uint32_t)jint(step, "protocol_version"),
                                          sid != NULL ? sid : s->session_id, ju64(step, "sequence"),
                                          dir_from(jstr(step, "direction")),
                                          jstr(step, "message_type"), &out, &out_len);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "aad bytes", (uint8_t *)out, out_len,
                            jstr(step, "expect_hex"));
        free(out);
        return fails;
    }

    if (strcmp(call, "derive_keys") == 0) {
        uint8_t psk[32], an[16], hn[16], th[32];
        ps4rf_keys keys;
        ps4rf_status st;
        if (decode_hex_field(step, "psk_hex", psk, 32, NULL) != 0 ||
            decode_hex_field(step, "agent_nonce_hex", an, 16, NULL) != 0 ||
            decode_hex_field(step, "host_nonce_hex", hn, 16, NULL) != 0 ||
            decode_hex_field(step, "transcript_hex", th, 32, NULL) != 0) {
            report(stage, vid, 1, "script hex lengths must be 32/16/16/32");
            return 1;
        }
        st = ps4rf_derive_keys(psk, an, hn, th, &keys);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK) {
            memcpy(ctx->keys.k_hs, keys.k_hs, 32);
            memcpy(ctx->keys.k_agent_to_host, keys.k_agent_to_host, 32);
            memcpy(ctx->keys.k_host_to_agent, keys.k_host_to_agent, 32);
            memcpy(ctx->transcript, th, 32);
            ctx->has_keys = 1;
            ctx->has_th = 1;
            if (geto(step, "expect_k_hs") != NULL)
                fails += eq_hex(stage, vid, "k_hs", keys.k_hs, 32, jstr(step, "expect_k_hs"));
            if (geto(step, "expect_k_agent_to_host") != NULL)
                fails += eq_hex(stage, vid, "k_agent_to_host", keys.k_agent_to_host, 32,
                                jstr(step, "expect_k_agent_to_host"));
            if (geto(step, "expect_k_host_to_agent") != NULL)
                fails += eq_hex(stage, vid, "k_host_to_agent", keys.k_host_to_agent, 32,
                                jstr(step, "expect_k_host_to_agent"));
        }
        return fails;
    }

    if (strcmp(call, "nonce_prefix") == 0) {
        uint8_t psk[32], an[16], hn[16], th[32], out[4];
        ps4rf_status st;
        if (decode_hex_field(step, "psk_hex", psk, 32, NULL) != 0 ||
            decode_hex_field(step, "agent_nonce_hex", an, 16, NULL) != 0 ||
            decode_hex_field(step, "host_nonce_hex", hn, 16, NULL) != 0 ||
            decode_hex_field(step, "transcript_hex", th, 32, NULL) != 0) {
            report(stage, vid, 1, "script hex lengths must be 32/16/16/32");
            return 1;
        }
        st = ps4rf_nonce_prefix(psk, an, hn, th, dir_from(jstr(step, "direction")), out);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "prefix", out, 4, jstr(step, "expect_hex"));
        return fails;
    }

    if (strcmp(call, "proof") == 0) {
        uint8_t k_hs[32], th[32], mac[32];
        ps4rf_status st;
        if (decode_hex_field(step, "k_hs_hex", k_hs, 32, NULL) != 0 ||
            decode_hex_field(step, "transcript_hex", th, 32, NULL) != 0) {
            report(stage, vid, 1, "script hex lengths must be 32/32");
            return 1;
        }
        st = ps4rf_proof(k_hs, jstr(step, "role"), th, mac);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "proof", mac, 32, jstr(step, "expect_hex"));
        return fails;
    }

    if (strcmp(call, "transcript") == 0) {
        uint8_t th[32];
        ps4rf_status st = ps4rf_transcript_hash(jstr(step, "hello_json"),
                                                strlen(jstr(step, "hello_json")),
                                                jstr(step, "ack_json"),
                                                strlen(jstr(step, "ack_json")), th);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "transcript", th, 32, jstr(step, "expect_hex"));
        return fails;
    }

    if (strcmp(call, "header_parse") == 0) {
        uint8_t raw[13];
        size_t raw_len = 0;
        char mtype[16];
        uint64_t seq = 0;
        uint32_t ct_len = 0;
        ps4rf_status st;
        if (decode_hex_field(step, "hex", raw, sizeof(raw), &raw_len) != 0 || raw_len != 13) {
            report(stage, vid, 1, "header hex must be 13 bytes");
            return 1;
        }
        st = ps4rf_frame_parse_header(raw, (size_t)jint(step, "max_frame_bytes"), mtype, &seq,
                                      &ct_len);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0) {
            if (geto(step, "expect_mtype") != NULL && strcmp(mtype, jstr(step, "expect_mtype")) != 0) {
                report(stage, vid, 1, "expected message type %s; got %s", jstr(step, "expect_mtype"),
                       mtype);
                fails++;
            }
            if (geto(step, "expect_seq") != NULL && seq != ju64(step, "expect_seq")) {
                report(stage, vid, 1, "expected sequence %llu; got %llu",
                       (unsigned long long)ju64(step, "expect_seq"), (unsigned long long)seq);
                fails++;
            }
        }
        return fails;
    }

    if (strcmp(call, "header_build") == 0) {
        uint8_t out[13];
        ps4rf_status st = ps4rf_frame_build_header((size_t)jint(step, "ct_len"),
                                                   jstr(step, "message_type"),
                                                   ju64(step, "sequence"),
                                                   jint(step, "allow_reserved"), out);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "header", out, 13, jstr(step, "expect_hex"));
        return fails;
    }

    if (strcmp(call, "wire_encode") == 0) {
        uint8_t pt[4096];
        size_t pt_len = 0;
        uint8_t *out = NULL;
        size_t out_len = 0;
        ps4rf_status st;
        if (!ctx->has_ch) {
            report(stage, vid, 1, "wire_encode without a channel");
            return 1;
        }
        if (decode_hex_field(step, "pt_hex", pt, sizeof(pt), &pt_len) != 0) {
            report(stage, vid, 1, "bad plaintext hex");
            return 1;
        }
        st = ps4rf_frame_encode(&ctx->ch, jstr(step, "mtype"), pt, pt_len, &out, &out_len,
                                jint(step, "allow_reserved"));
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "frame", out, out_len, jstr(step, "expect_hex"));
        free(out);
        return fails;
    }

    if (strcmp(call, "wire_decode") == 0) {
        uint8_t frame[8192];
        size_t frame_len = 0;
        char mtype[16];
        uint64_t seq = 0;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        ps4rf_status st;
        if (!ctx->has_ch) {
            report(stage, vid, 1, "wire_decode without a channel");
            return 1;
        }
        if (decode_hex_field(step, "wire_hex", frame, sizeof(frame), &frame_len) != 0) {
            report(stage, vid, 1, "bad frame hex");
            return 1;
        }
        st = ps4rf_frame_decode(&ctx->ch, frame, frame_len, mtype, &seq, &pt, &pt_len);
        fails += expect_status(vid, stage, st, step);
        if (st == PS4RF_OK && expect != NULL && strcmp(expect, "ok") == 0)
            fails += eq_hex(stage, vid, "plaintext", pt, pt_len, jstr(step, "expect_hex"));
        free(pt);
        return fails;
    }

    if (strcmp(call, "direction_check") == 0) {
        ps4rf_status st = ps4rf_direction_check(dir_from(jstr(step, "direction")),
                                                jstr(step, "message_type"));
        fails += expect_status(vid, stage, st, step);
        return fails;
    }

    if (strcmp(call, "hs_send_oversize") == 0) {
        const char *json = jstr(step, "json");
        jval *obj = jval_parse(json, strlen(json));
        ps4rf_status st;
        if (obj == NULL) {
            report(stage, vid, 1, "script object did not parse");
            return 1;
        }
        /* fd -1: the size check must refuse the frame before any socket call */
        st = ps4rf_hs_send(-1, obj);
        fails += expect_status(vid, stage, st, step);
        jval_free(obj);
        return fails;
    }

    if (strcmp(call, "handshake") == 0) {
        const char *role = jstr(step, "role");
        const char *counterpart = jstr(step, "counterpart");
        uint8_t psk[32];
        jval *hello = NULL, *ack = NULL;
        int fds[2] = {-1, -1};
        pthread_t thread;
        hs_ctx hc;
        ps4rf_status main_st;
        if (decode_hex_field(step, "psk_hex", psk, 32, NULL) != 0) {
            report(stage, vid, 1, "script psk must be 32 bytes");
            return 1;
        }
        hello = jval_parse(jstr(step, "hello_json"), strlen(jstr(step, "hello_json")));
        ack = jval_parse(jstr(step, "ack_json"), strlen(jstr(step, "ack_json")));
        if (hello == NULL || ack == NULL || socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            report(stage, vid, 1, "handshake setup failed");
            jval_free(hello);
            jval_free(ack);
            return 1;
        }
        memset(&hc, 0, sizeof(hc));
        hc.fd = fds[1];
        memcpy(hc.psk, psk, 32);
        memcpy(hc.agent_nonce, s->agent_nonce, 16);
        memcpy(hc.host_nonce, s->host_nonce, 16);
        hc.hello = hello;
        hc.ack = ack;
        hc.role = role;
        hc.counterpart = counterpart;
        hc.hello_json = jstr(step, "hello_json");
        hc.ack_mutated_json = jstr(step, "ack_mutated_json");
        if (pthread_create(&thread, NULL, hs_counterpart_thread, &hc) != 0) {
            report(stage, vid, 1, "pthread_create failed");
            close(fds[0]);
            close(fds[1]);
            jval_free(hello);
            jval_free(ack);
            return 1;
        }
        if (strcmp(role, "agent") == 0)
            main_st = ps4rf_agent_handshake(fds[0], psk, hello, &ctx->keys, NULL);
        else
            main_st = ps4rf_host_handshake(fds[0], psk, ack, &ctx->keys, NULL);
        close(fds[0]); /* rogue counterparts may be waiting for EOF */
        pthread_join(thread, NULL);
        if (strcmp(counterpart, "catalog") == 0 && main_st == PS4RF_OK) {
            ctx->has_keys = 1;
            if (hc.status != PS4RF_OK) {
                report(stage, vid, 1, "counterpart side failed with %s",
                       ps4rf_status_name(hc.status));
                fails++;
            } else if (hc.keys_valid && memcmp(hc.keys.k_hs, ctx->keys.k_hs, 32) != 0) {
                report(stage, vid, 1, "the two sides derived different handshake keys");
                fails++;
            } else if (memcmp(ctx->keys.k_hs, s->k_hs, 32) != 0) {
                report(stage, vid, 1, "handshake keys differ from the golden session");
                fails++;
            } else {
                fails += expect_status(vid, stage, main_st, step);
            }
        } else {
            fails += expect_status(vid, stage, main_st, step);
        }
        jval_free(hello);
        jval_free(ack);
        return fails;
    }

    report(stage, vid, 1, "unknown script call %s", call);
    return 1;
}

static int run_script_cases(const jval *neg, const session_t *s)
{
    const char *sections[3];
    int fails = 0;
    size_t sec, i, k;
    sections[0] = "boundaries";
    sections[1] = "negative";
    sections[2] = "parity_cases";
    for (sec = 0; sec < 3; sec++) {
        const jval *arr = geto(neg, sections[sec]);
        size_t n = jval_count(arr);
        for (i = 0; i < n; i++) {
            const jval *c = jval_at(arr, i);
            const jval *steps = geto(c, "steps");
            const jval *structural = geto(c, "structural");
            const char *case_id = jstr(c, "id");
            script_ctx ctx;
            char full_id[192];
            size_t step_n, j;
            memset(&ctx, 0, sizeof(ctx));
            snprintf(full_id, sizeof(full_id), "%s/%s", nn(sections[sec]), nn(case_id));
            if (structural != NULL && jval_kind(structural) == JVAL_BOOL && jval_bool(structural)) {
                const char *reason = jstr(c, "structural_reason");
                report(jstr(c, "stage"), full_id, 2, "%s",
                       reason != NULL ? reason : "not representable natively");
                continue;
            }
            step_n = jval_count(steps);
            if (step_n == 0) {
                report(jstr(c, "stage"), full_id, 1, "case has no steps");
                fails++;
                continue;
            }
            for (j = 0; j < step_n; j++) {
                const jval *step = jval_at(steps, j);
                int step_fail = run_step(&ctx, step, full_id, s);
                if (step_fail == 0 && j == step_n - 1) {
                    const char *desc = jstr(c, "description");
                    report(jstr(c, "stage"), full_id, 0, "%s",
                           desc != NULL ? desc : "matched the reference outcome");
                } else if (step_fail != 0) {
                    fails += step_fail;
                    break;
                }
                (void)k;
            }
        }
    }
    return fails;
}

/* --------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    const char *crypto_path = argc > 1 ? argv[1] : "tests/fixtures/crypto/vectors-v1.json";
    const char *parity_path = argc > 2 ? argv[2] : "tests/fixtures/parity/vectors-v1.json";
    const char *negative_path = argc > 3 ? argv[3] : "tests/fixtures/parity/w2-negative-v1.json";
    char *crypto_text, *parity_text, *neg_text;
    jval *crypto, *parity, *neg;
    session_t session;
    int fails = 0;
    int i;

    if (getenv("PS4RF_HARNESS_VERBOSE") != NULL) verbose = 1;

    crypto_text = read_file(crypto_path, NULL);
    parity_text = read_file(parity_path, NULL);
    neg_text = read_file(negative_path, NULL);
    if (crypto_text == NULL || parity_text == NULL || neg_text == NULL) return 2;
    crypto = jval_parse(crypto_text, strlen(crypto_text));
    parity = jval_parse(parity_text, strlen(parity_text));
    neg = jval_parse(neg_text, strlen(neg_text));
    if (crypto == NULL || parity == NULL || neg == NULL) {
        fprintf(stderr, "catalog parse failed\n");
        return 2;
    }
    if (load_session(crypto, parity, &session) != 0) {
        fprintf(stderr, "session material could not be loaded\n");
        return 2;
    }

    printf("PS4RF W2 parity harness -- native protocol core vs golden catalogs\n");
    printf("crypto catalog:   %s\n", crypto_path);
    printf("parity catalog:   %s\n", parity_path);
    printf("negative catalog: %s\n\n", negative_path);

    fails += check_crypto_rfc(crypto);
    fails += check_crypto_protocol(crypto, &session);
    fails += check_crypto_frames(crypto, &session);
    fails += check_parity(parity, crypto, &session);
    fails += run_script_cases(neg, &session);

    printf("\n%-16s %6s %6s %6s\n", "stage", "PASS", "FAIL", "SKIP");
    {
        int pass_total = 0, fail_total = 0, skip_total = 0;
        for (i = 0; i < STAGE_COUNT; i++) {
            printf("%-16s %6d %6d %6d\n", STAGES[i], counts[i][0], counts[i][1], counts[i][2]);
            pass_total += counts[i][0];
            fail_total += counts[i][1];
            skip_total += counts[i][2];
        }
        printf("%-16s %6d %6d %6d\n", "TOTAL", pass_total, fail_total, skip_total);
        printf("\nparity verdict: %s\n", fail_total == 0 ? "PASS" : "FAIL");
    }
    jval_free(crypto);
    jval_free(parity);
    jval_free(neg);
    free(crypto_text);
    free(parity_text);
    free(neg_text);
    return fails == 0 ? 0 : 1;
}
