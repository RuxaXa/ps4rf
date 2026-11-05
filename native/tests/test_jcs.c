/*
 * ps4rf/native/tests/test_jcs.c
 *
 * Byte-parity self-test for native/src/jcs.[ch] against the golden vectors in
 * tests/fixtures/crypto/vectors-v1.json (schema ps4rf-crypto-vectors-v1).
 *
 * Build and run:
 *   gcc -std=c99 -O2 -Wall -Wextra -Werror -o /tmp/test_jcs \
 *       native/tests/test_jcs.c native/src/jcs.c
 *   (cd <repo root> && /tmp/test_jcs)          # or: /tmp/test_jcs <catalog path>
 * The catalog path may also be given via $PS4RF_VECTORS.
 *
 * Acceptance coverage:
 *   1. rfc_vectors.rfc8785_appendix_b (24 cases): IEEE-754 bits -> double ->
 *      jcs_format_double must equal the vector's `json` string exactly.
 *   2. rfc_vectors.rfc8785_sample: jcs_serialize_text(input_json) must equal
 *      canonical_utf8_hex byte for byte.
 *   3. protocol.objects hello / hello_ack: ps4rf_canonical_bytes_text on the
 *      exchange JSON text must equal hello_canonical_hex / hello_ack_canonical_hex.
 *   4. boundaries: value-level safe-number policy cases (ok + result hex, or
 *      raises + exception name) mirroring core/canonical.py.
 *   5. UTF-16 code-unit key ordering (astral sorts before U+FFFD).
 * Plus escape-table, builder-API, syntax-rejection and formatter edge checks.
 *
 * Prints one PASS line per case; exits non-zero on any failure.
 */

#include "../src/jcs.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass;
static int g_fail;

#define PASS(...)                        \
    do {                                 \
        g_pass++;                        \
        printf("PASS ");                 \
        printf(__VA_ARGS__);             \
        putchar('\n');                   \
    } while (0)

#define FAIL(...)                        \
    do {                                 \
        g_fail++;                        \
        printf("FAIL ");                 \
        printf(__VA_ARGS__);             \
        putchar('\n');                   \
    } while (0)

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static char *slurp(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;
    size_t n;
    if (f == NULL) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    *out_len = n;
    return buf;
}

static int hex_nibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static unsigned char *hex_decode(const char *hex, size_t *out_len)
{
    size_t n = strlen(hex), i;
    unsigned char *b;
    if (n % 2 != 0) return NULL;
    b = (unsigned char *)malloc(n / 2 + 1);
    if (b == NULL) return NULL;
    for (i = 0; i < n / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(b);
            return NULL;
        }
        b[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return b;
}

static void dump_hex(const char *label, const unsigned char *b, size_t n)
{
    size_t i, lim = n > 200 ? 200 : n;
    printf("  %s (%zu bytes): ", label, n);
    for (i = 0; i < lim; i++) printf("%02x", b[i]);
    if (lim < n) printf("...");
    putchar('\n');
}

static const jval *find_boundary(const jval *cat, const char *id)
{
    const jval *bs = jval_get(cat, "boundaries");
    size_t i, n = jval_count(bs);
    for (i = 0; i < n; i++) {
        const jval *b = jval_at(bs, i);
        size_t idlen = 0;
        const char *bid = jval_string(jval_get(b, "id"), &idlen);
        if (bid != NULL && strcmp(bid, id) == 0) return b;
    }
    return NULL;
}

/* white-box constructors for the two states the frozen builder API cannot
 * express (see jcs.h): a raw IEEE-754 double value and, separately, a
 * non-string object key. */
static jval *wb_new_double(double d)
{
    jval *v = jval_new_null();
    if (v == NULL) return NULL;
    v->type = JVAL_DOUBLE;
    v->u.d = d;
    return v;
}

/* ------------------------------------------------------------------ */
/* vector extraction (embedded, extracted from the catalog with python3) */
/* ------------------------------------------------------------------ */

/* hello / hello_ack exchange JSON texts. Extracted from
 * tests/fixtures/crypto/vectors-v1.json with python3 (stdlib json only):
 *
 *   python3 -c "import json;c=json.load(open('tests/fixtures/crypto/vectors-v1.json'));
 *   d=c['protocol']['objects']['hello'];print(json.dumps(dict(reversed(list(d.items()))),
 *   separators=(', ', ': ')))"
 *
 * Key order is deliberately reversed (and separators are non-canonical) so
 * the canonicalizer has to sort and squeeze whitespace. */
static const char hello_json[] =
    "{\"transport\": \"vector-transport\", \"recovery_required\": false, "
    "\"provider\": \"vector-provider\", \"nonce\": \"000102030405060708090a0b0c0d0e0f\", "
    "\"msg\": \"HELLO\", \"label\": \"ps4rf-handshake-v1\", \"context\": \"vector-context\", "
    "\"agent_version\": \"vector-0.1.0\"}";

static const char hello_ack_json[] =
    "{\"session_id\": \"SES-0123456789ABCDEF\", \"protocol_version\": 1, "
    "\"nonce\": \"101112131415161718191a1b1c1d1e1f\", \"msg\": \"HELLO_ACK\", "
    "\"limits\": {\"max_chunk_bytes\": 1048576, \"max_ir_bytes\": 262144}, "
    "\"auth_required\": true, \"aead\": \"AEAD_CHACHA20_POLY1305\"}";

/* ------------------------------------------------------------------ */
/* test 1: RFC 8785 appendix B number vectors                          */
/* ------------------------------------------------------------------ */

static void test_appendix_b(const jval *cat)
{
    const jval *ab = jval_get(jval_get(cat, "rfc_vectors"), "rfc8785_appendix_b");
    size_t n = jval_count(ab), i;

    if (jval_kind(ab) != JVAL_ARRAY) {
        FAIL("appendix_b: catalog section missing or not an array");
        return;
    }
    if (n != 24) {
        FAIL("appendix_b: expected 24 vectors, catalog has %zu", n);
        return;
    }
    for (i = 0; i < n; i++) {
        const jval *e = jval_at(ab, i);
        size_t hl = 0, jl = 0;
        const char *hex = jval_string(jval_get(e, "ieee754"), &hl);
        const char *exp = jval_string(jval_get(e, "json"), &jl);
        uint64_t bits = 0;
        double d;
        char buf[64];
        int b, hexbad = 0;

        if (hex == NULL || hl != 16 || exp == NULL || jl == 0) {
            FAIL("appendix_b[%zu]: malformed catalog entry", i + 1);
            continue;
        }
        for (b = 0; b < 8; b++) {
            int hi = hex_nibble(hex[2 * b]);
            int lo = hex_nibble(hex[2 * b + 1]);
            if (hi < 0 || lo < 0) {
                hexbad = 1;
                break;
            }
            bits = (bits << 8) | (uint64_t)((hi << 4) | lo);
        }
        if (hexbad) {
            FAIL("appendix_b[%zu]: bad ieee754 hex '%s'", i + 1, hex);
            continue;
        }
        memcpy(&d, &bits, sizeof d);
        if (jcs_format_double(d, buf, sizeof buf) != 0) {
            FAIL("appendix_b[%zu] ieee754=%s: jcs_format_double error", i + 1, hex);
            continue;
        }
        if (strcmp(buf, exp) == 0) {
            PASS("appendix_b[%02zu/24] ieee754=%s -> %s", i + 1, hex, buf);
        } else {
            FAIL("appendix_b[%02zu/24] ieee754=%s expected '%s' got '%s'", i + 1, hex, exp, buf);
        }
    }
}

/* ------------------------------------------------------------------ */
/* test 2: RFC 8785 sample vector                                      */
/* ------------------------------------------------------------------ */

static void test_sample(const jval *cat)
{
    const jval *s = jval_get(jval_get(cat, "rfc_vectors"), "rfc8785_sample");
    size_t ilen = 0, hlen = 0, elen = 0, outlen = 0;
    const jval *input_v = jval_get(s, "input_json");
    const char *input = jval_string(input_v, &ilen);
    const char *hex = jval_string(jval_get(s, "canonical_utf8_hex"), &hlen);
    unsigned char *exp;
    char *out = NULL;

    if (input == NULL || hex == NULL) {
        FAIL("sample: catalog entry missing");
        return;
    }
    exp = hex_decode(hex, &elen);
    if (exp == NULL) {
        FAIL("sample: bad canonical_utf8_hex");
        return;
    }
    if (jcs_serialize_text(input, ilen, &out, &outlen) != 0) {
        FAIL("sample: jcs_serialize_text returned -1");
    } else if (outlen == elen && memcmp(out, exp, elen) == 0) {
        PASS("rfc8785_sample: %zu input bytes -> %zu canonical bytes == canonical_utf8_hex", ilen, outlen);
    } else {
        FAIL("rfc8785_sample mismatch: got %zu bytes, expected %zu", outlen, elen);
        if (out != NULL) dump_hex("got", (const unsigned char *)out, outlen);
        dump_hex("expected", exp, elen);
    }
    free(out);
    free(exp);
}

/* ------------------------------------------------------------------ */
/* test 3: protocol hello / hello_ack canonical bytes                  */
/* ------------------------------------------------------------------ */

static void test_protocol_object(const jval *cat, const char *name, const char *text, const char *hexkey)
{
    const jval *ex = jval_get(jval_get(cat, "protocol"), "exchange");
    size_t hlen = 0, elen = 0, tlen = strlen(text), outlen = 0;
    const char *hex = jval_string(jval_get(ex, hexkey), &hlen);
    unsigned char *exp;
    char *out = NULL;
    const char *err = NULL;
    jval *v = NULL;

    if (hex == NULL) {
        FAIL("protocol.%s: catalog key %s missing", name, hexkey);
        return;
    }
    exp = hex_decode(hex, &elen);
    if (exp == NULL) {
        FAIL("protocol.%s: bad %s hex", name, hexkey);
        return;
    }

    if (ps4rf_canonical_bytes_text(text, tlen, &out, &outlen, &err) != 0) {
        FAIL("protocol.%s: ps4rf_canonical_bytes_text failed (%s)", name, err != NULL ? err : "?");
    } else if (outlen == elen && memcmp(out, exp, elen) == 0) {
        PASS("protocol.%s: text path canonical %zu bytes == %s (%zu bytes)", name, outlen, hexkey, elen);
    } else {
        FAIL("protocol.%s mismatch (text path): got %zu bytes, expected %zu", name, outlen, elen);
        if (out != NULL) dump_hex("got", (const unsigned char *)out, outlen);
        dump_hex("expected", exp, elen);
    }
    free(out);
    out = NULL;
    outlen = 0;

    v = jval_parse(text, tlen);
    if (v == NULL) {
        FAIL("protocol.%s: embedded JSON text did not parse", name);
    } else {
        err = NULL;
        if (ps4rf_canonical_bytes(v, &out, &outlen, &err) != 0) {
            FAIL("protocol.%s: value path failed (%s)", name, err != NULL ? err : "?");
        } else if (outlen == elen && memcmp(out, exp, elen) == 0) {
            PASS("protocol.%s: value path canonical equals %s", name, hexkey);
        } else {
            FAIL("protocol.%s mismatch (value path): got %zu bytes, expected %zu", name, outlen, elen);
        }
    }
    free(out);
    jval_free(v);
    free(exp);
}

/* ------------------------------------------------------------------ */
/* test 4: boundaries (policy layer)                                   */
/* ------------------------------------------------------------------ */

static void test_boundary_ok(const jval *cat, const char *id, const char *text)
{
    const jval *b = find_boundary(cat, id);
    size_t ol = 0, hlen = 0, elen = 0, outlen = 0;
    const char *outcome, *hex;
    unsigned char *exp;
    char *out = NULL;
    const char *err = NULL;

    if (b == NULL) {
        FAIL("boundary %s: not present in catalog", id);
        return;
    }
    outcome = jval_string(jval_get(b, "outcome"), &ol);
    hex = jval_string(jval_get(b, "result"), &hlen);
    if (outcome == NULL || strcmp(outcome, "ok") != 0 || hex == NULL) {
        FAIL("boundary %s: catalog entry is not an ok+result case", id);
        return;
    }
    exp = hex_decode(hex, &elen);
    if (exp == NULL) {
        FAIL("boundary %s: bad result hex", id);
        return;
    }
    if (ps4rf_canonical_bytes_text(text, strlen(text), &out, &outlen, &err) != 0) {
        FAIL("boundary %s: expected ok, got -1 (%s) for input %s", id, err != NULL ? err : "?", text);
    } else if (outlen == elen && memcmp(out, exp, elen) == 0) {
        PASS("boundary %s: %s -> %zu bytes == result hex", id, text, outlen);
    } else {
        FAIL("boundary %s: mismatch for %s: got %zu bytes, expected %zu", id, text, outlen, elen);
        if (out != NULL) dump_hex("got", (const unsigned char *)out, outlen);
        dump_hex("expected", exp, elen);
    }
    free(out);
    free(exp);
}

static const char *catalog_exception(const jval *cat, const char *id)
{
    const jval *b = find_boundary(cat, id);
    size_t l = 0;
    const char *outcome, *want;
    if (b == NULL) return NULL;
    outcome = jval_string(jval_get(b, "outcome"), &l);
    if (outcome == NULL || strcmp(outcome, "raises") != 0) return NULL;
    want = jval_string(jval_get(b, "exception"), &l);
    return want;
}

static void test_boundary_raises_text(const jval *cat, const char *id, const char *text)
{
    const char *want = catalog_exception(cat, id);
    const char *err = NULL;
    char *out = NULL;
    size_t outlen = 0;
    int rc;

    if (want == NULL) {
        FAIL("boundary %s: catalog entry is not a raises case", id);
        return;
    }
    rc = ps4rf_canonical_bytes_text(text, strlen(text), &out, &outlen, &err);
    if (rc == 0) {
        FAIL("boundary %s: expected %s for '%s', got ok (%zu bytes)", id, want, text, outlen);
    } else if (err != NULL && strcmp(err, want) == 0) {
        PASS("boundary %s: '%s' -> %s (as cataloged)", id, text, want);
    } else {
        FAIL("boundary %s: expected %s for '%s', got '%s'", id, want, text, err != NULL ? err : "?");
    }
    free(out);
}

static void test_boundary_raises_value(const jval *cat, const char *id, jval *v, const char *label)
{
    const char *want = catalog_exception(cat, id);
    const char *err = NULL;
    char *out = NULL;
    size_t outlen = 0;
    int rc;

    if (want == NULL) {
        FAIL("boundary %s: catalog entry is not a raises case", id);
        jval_free(v);
        return;
    }
    rc = ps4rf_canonical_bytes(v, &out, &outlen, &err);
    if (rc == 0) {
        FAIL("boundary %s: expected %s for %s, got ok (%zu bytes)", id, want, label, outlen);
    } else if (err != NULL && strcmp(err, want) == 0) {
        PASS("boundary %s: %s -> %s (white-box value, as cataloged)", id, label, want);
    } else {
        FAIL("boundary %s: expected %s for %s, got '%s'", id, want, label, err != NULL ? err : "?");
    }
    free(out);
    jval_free(v);
}

static void test_nonstring_key(const jval *cat)
{
    const char *want = catalog_exception(cat, "canonical_nonstring_key");
    jval *o, *v;
    const char *err = NULL;
    char *out = NULL;
    size_t outlen = 0;
    int rc;

    if (want == NULL) {
        FAIL("boundary canonical_nonstring_key: not cataloged as raises");
        return;
    }

    /* Builder level: the frozen API takes `const char *key`, so a non-string
     * key is not constructible; the builder refuses NULL and does NOT take
     * ownership of the value. */
    o = jval_new_object();
    v = jval_new_int(5);
    if (o == NULL || v == NULL) {
        FAIL("boundary canonical_nonstring_key: allocation failure");
    } else if (jval_obj_set(o, NULL, v) == -1) {
        PASS("boundary canonical_nonstring_key: builder refuses NULL (non-string) key; value ownership retained");
    } else {
        FAIL("boundary canonical_nonstring_key: jval_obj_set(NULL key) unexpectedly succeeded");
    }
    jval_free(v);
    jval_free(o);

    /* Policy level: white-box a member whose stored key is not a string
     * (the internal representation of a non-string key; see jcs.h). */
    o = jval_new_object();
    if (o == NULL || jval_obj_set(o, "k", jval_new_int(1)) != 0) {
        FAIL("boundary canonical_nonstring_key: could not build white-box object");
        jval_free(o);
        return;
    }
    free(o->u.o.m[0].key); /* same allocator as jcs.c */
    o->u.o.m[0].key = NULL;
    o->u.o.m[0].klen = 0;

    rc = ps4rf_canonical_bytes(o, &out, &outlen, &err);
    if (rc == 0) {
        FAIL("boundary canonical_nonstring_key: expected %s, got ok (%zu bytes)", want, outlen);
    } else if (err != NULL && strcmp(err, want) == 0) {
        PASS("boundary canonical_nonstring_key: non-string key -> %s (white-box injection; public API cannot express it)", want);
    } else {
        FAIL("boundary canonical_nonstring_key: expected %s, got '%s'", want, err != NULL ? err : "?");
    }
    free(out);
    jval_free(o);
}

/* ------------------------------------------------------------------ */
/* test 5: UTF-16 code-unit key ordering                               */
/* ------------------------------------------------------------------ */

static void test_key_order(void)
{
    struct { const char *input; const char *want; } cases[3];
    size_t i;

    cases[0].input = "{\"\\uFFFD\":1,\"\\ud83d\\ude00\":2,\"a\":3,\"A\":4,\"\\u20ac\":5}";
    cases[0].want = "{\"A\":4,\"a\":3,\""
                    "\xE2\x82\xAC"
                    "\":5,\""
                    "\xF0\x9F\x98\x80"
                    "\":2,\""
                    "\xEF\xBF\xBD"
                    "\":1}";
    cases[1].input = "{\"\\ud83d\\ude00\":1,\"\\ud83d\\ude01\":2}";
    cases[1].want = "{\""
                    "\xF0\x9F\x98\x80"
                    "\":1,\""
                    "\xF0\x9F\x98\x81"
                    "\":2}";
    cases[2].input = "{\"b\":1,\"a\":2,\"B\":3}";
    cases[2].want = "{\"B\":3,\"a\":2,\"b\":1}";

    for (i = 0; i < 3; i++) {
        char *out = NULL;
        size_t outlen = 0;
        if (jcs_serialize_text(cases[i].input, strlen(cases[i].input), &out, &outlen) != 0) {
            FAIL("key_order[%zu]: serialize failed for %s", i, cases[i].input);
            free(out);
            continue;
        }
        if (strcmp(out, cases[i].want) == 0) {
            PASS("key_order[%zu]: %s -> %s", i, cases[i].input, out);
        } else {
            FAIL("key_order[%zu]: %s expected %s got %s", i, cases[i].input, cases[i].want, out);
        }
        if (i == 0) {
            const char *astral = strstr(out, "\xF0\x9F\x98\x80"); /* U+1F600 */
            const char *fffd = strstr(out, "\xEF\xBF\xBD");       /* U+FFFD */
            if (astral != NULL && fffd != NULL && astral < fffd) {
                PASS("key_order: astral U+1F600 precedes U+FFFD (UTF-16 code units;"
                     " raw UTF-8 byte order would invert it)");
            } else {
                FAIL("key_order: astral/U+FFFD discriminating assertion failed");
            }
        }
        free(out);
    }
}

/* ------------------------------------------------------------------ */
/* extra coverage: escapes, literals, builder, syntax, formatter edges */
/* ------------------------------------------------------------------ */

static void test_escapes(void)
{
    struct { const char *input; const char *want; const char *label; } cases[3];
    size_t i;

    cases[0].input = "[\"\\b\\f\\t\\u0001\\r\\n\\\"\\\\\\/\"]";
    cases[0].want = "[\"\\b\\f\\t\\u0001\\r\\n\\\"\\\\/\"]";
    cases[0].label = "control escapes + quote/backslash/solidus";
    cases[1].input = "[\"\\u0000\"]";
    cases[1].want = "[\"\\u0000\"]";
    cases[1].label = "U+0000 code point";
    cases[2].input = "{\"\\u001f\":1,\"\\u007f\":2}";
    cases[2].want = "{\"\\u001f\":1,\"" "\x7f" "\":2}";
    cases[2].label = "C0 key escaped, U+007F raw";

    for (i = 0; i < 3; i++) {
        char *out = NULL;
        size_t outlen = 0;
        if (jcs_serialize_text(cases[i].input, strlen(cases[i].input), &out, &outlen) != 0) {
            FAIL("escape[%zu] (%s): serialize failed", i, cases[i].label);
        } else if (strcmp(out, cases[i].want) == 0) {
            PASS("escape[%zu] (%s): %s", i, cases[i].label, out);
        } else {
            FAIL("escape[%zu] (%s): expected %s got %s", i, cases[i].label, cases[i].want, out);
        }
        free(out);
    }
}

static void test_literals(void)
{
    struct { const char *input; const char *want; } cases[14];
    size_t i;
    int bad = 0;

    cases[0].input = "0";        cases[0].want = "0";
    cases[1].input = "-0";       cases[1].want = "0";
    cases[2].input = "123";      cases[2].want = "123";
    cases[3].input = "-123";     cases[3].want = "-123";
    cases[4].input = "{}";       cases[4].want = "{}";
    cases[5].input = "[]";       cases[5].want = "[]";
    cases[6].input = "[1,[2],{}]"; cases[6].want = "[1,[2],{}]";
    cases[7].input = "true";     cases[7].want = "true";
    cases[8].input = "false";    cases[8].want = "false";
    cases[9].input = "null";     cases[9].want = "null";
    cases[10].input = "\"a\"";   cases[10].want = "\"a\"";
    cases[11].input = "1.0";     cases[11].want = "1";
    cases[12].input = "1e0";     cases[12].want = "1";
    cases[13].input = "0.5";     cases[13].want = "0.5";

    for (i = 0; i < 14; i++) {
        char *out = NULL;
        size_t outlen = 0;
        if (jcs_serialize_text(cases[i].input, strlen(cases[i].input), &out, &outlen) != 0) {
            FAIL("literal '%s': serialize failed", cases[i].input);
            bad = 1;
        } else if (strcmp(out, cases[i].want) != 0) {
            FAIL("literal '%s': expected %s got %s", cases[i].input, cases[i].want, out);
            bad = 1;
        }
        free(out);
    }
    if (!bad) PASS("literals: 14/14 scalar/container forms canonicalize as expected");
}

static void test_builder_api(void)
{
    jval *o = jval_new_object();
    jval *arr = jval_new_array();
    jval *v;
    char *out = NULL;
    size_t outlen = 0, slen = 0;
    const char *s;
    int ok = 1;

    if (o == NULL || arr == NULL) {
        FAIL("builder: allocation failure");
        jval_free(o);
        jval_free(arr);
        return;
    }
    ok &= jval_obj_set(o, "n", jval_new_null()) == 0;
    ok &= jval_obj_set(o, "b", jval_new_bool(1)) == 0;
    ok &= jval_obj_set(o, "i", jval_new_int(42)) == 0;
    ok &= jval_obj_set(o, "s", jval_new_string("x")) == 0;
    ok &= jval_arr_add(arr, jval_new_int(7)) == 0;
    ok &= jval_obj_set(o, "a", arr) == 0;
    ok &= jval_obj_set(o, "i", jval_new_int(43)) == 0; /* replace, dict semantics */

    v = jval_new_int(9);
    ok &= jval_obj_set(o, NULL, v) == -1;      /* non-string key refused */
    jval_free(v);
    v = jval_new_int(9);
    ok &= jval_obj_set(NULL, "k", v) == -1;    /* not an object */
    jval_free(v);
    v = jval_new_int(9);
    ok &= jval_obj_set(o, "z", NULL) == -1;    /* NULL value refused */
    jval_free(v);
    v = jval_new_int(1);
    ok &= jval_arr_add(o, v) == -1;      /* not an array; caller retains value */
    jval_free(v);
    ok &= jval_arr_add(arr, NULL) == -1;
    ok &= jval_get(o, NULL) == NULL;
    ok &= jval_get(arr, "x") == NULL;          /* not an object */
    ok &= jval_at(arr, 5) == NULL;             /* out of bounds */
    ok &= jval_key_at(o, jval_count(o)) == NULL;
    ok &= jval_kind(jval_get(o, "i")) == JVAL_INT && jval_int(jval_get(o, "i")) == 43;
    ok &= jval_double(jval_get(o, "i")) == 43.0;
    ok &= jval_bool(jval_get(o, "b")) == 1;
    s = jval_string(jval_get(o, "s"), &slen);
    ok &= s != NULL && slen == 1 && strcmp(s, "x") == 0;
    ok &= jval_count(o) == 5 && jval_count(arr) == 1;
    ok &= jval_at(arr, 0) != NULL && jval_int(jval_at(arr, 0)) == 7;

    if (!ok) {
        FAIL("builder: accessor/ownership checks failed");
    } else if (jcs_serialize(o, &out, &outlen) == 0 &&
               strcmp(out, "{\"a\":[7],\"b\":true,\"i\":43,\"n\":null,\"s\":\"x\"}") == 0) {
        PASS("builder: constructors/accessors/ownership ok; serialized %s", out);
    } else {
        FAIL("builder: unexpected serialization '%s'", out != NULL ? out : "(null)");
    }
    free(out);
    jval_free(o);
}

static void test_syntax_rejects(void)
{
    static const char *bad_inputs[] = {
        "{" , "[1,]" , "[1 2]" , "{\"a\":1,}" , "nul" , "tru" , "01" , "-" , "1." ,
        "1e" , "+1" , ".5" , "NaNx" , "\"\\ud800\"" , "\"\\udc00\"" ,
        "\"unterminated" , "{} {}" , "[" , "1.2.3" , "\x01" , "" , "   " , "0x1"
    };
    size_t n = sizeof bad_inputs / sizeof bad_inputs[0], i;
    size_t rejected = 0;

    for (i = 0; i < n; i++) {
        jval *v = jval_parse(bad_inputs[i], strlen(bad_inputs[i]));
        if (v == NULL) rejected++;
        else jval_free(v);
    }
    if (rejected == n) {
        PASS("syntax_reject: %zu/%zu malformed inputs rejected", rejected, n);
    } else {
        FAIL("syntax_reject: only %zu/%zu malformed inputs rejected", rejected, n);
    }
}

static void test_formatter_edges(void)
{
    char buf[64];

    if (jcs_format_double((double)NAN, buf, sizeof buf) == -1) PASS("format: NaN -> -1");
    else FAIL("format: NaN unexpectedly formatted");

    if (jcs_format_double((double)INFINITY, buf, sizeof buf) == -1) PASS("format: +Infinity -> -1");
    else FAIL("format: +Infinity unexpectedly formatted");

    if (jcs_format_double(-(double)INFINITY, buf, sizeof buf) == -1) PASS("format: -Infinity -> -1");
    else FAIL("format: -Infinity unexpectedly formatted");

    if (jcs_format_double(-0.0, buf, sizeof buf) == 0 && strcmp(buf, "0") == 0) PASS("format: -0.0 -> 0");
    else FAIL("format: -0.0 -> '%s'", buf);

    if (jcs_format_double(1.5, buf, 3) == -1) PASS("format: insufficient cap -> -1");
    else FAIL("format: small cap did not fail");

    if (jcs_format_double(1.5, buf, 4) == 0 && strcmp(buf, "1.5") == 0) PASS("format: exact-fit cap ok");
    else FAIL("format: exact-fit cap failed");

    {
        jval *v = jval_new_int(INT64_C(9007199254740992)); /* 2^53, mirrors IntegerDomainError */
        char *out = NULL;
        size_t outlen = 0;
        if (v != NULL && jcs_serialize(v, &out, &outlen) == -1) {
            PASS("serialize: integer beyond +/- (2^53-1) -> -1 (mirrors rfc8785 IntegerDomainError)");
        } else {
            FAIL("serialize: integer beyond +/- (2^53-1) unexpectedly accepted");
        }
        free(out);
        jval_free(v);
    }
    if (jcs_serialize_text("NaN", 3, NULL, NULL) == -1) { /* NULL out also rejected */
        PASS("serialize_text: non-finite text -> -1");
    } else {
        FAIL("serialize_text: non-finite text unexpectedly accepted");
    }
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    static const char *candidates[] = {
        "tests/fixtures/crypto/vectors-v1.json",
        "../tests/fixtures/crypto/vectors-v1.json",
        "../../tests/fixtures/crypto/vectors-v1.json",
        "../../../tests/fixtures/crypto/vectors-v1.json"
    };
    char *buf = NULL;
    size_t blen = 0, i;
    jval *cat;
    const char *envp;

    if (argc > 1) buf = slurp(argv[1], &blen);
    if (buf == NULL) {
        envp = getenv("PS4RF_VECTORS");
        if (envp != NULL && *envp != '\0') buf = slurp(envp, &blen);
    }
    for (i = 0; buf == NULL && i < sizeof candidates / sizeof candidates[0]; i++) {
        buf = slurp(candidates[i], &blen);
    }
    if (buf == NULL) {
        fprintf(stderr,
                "test_jcs: cannot read tests/fixtures/crypto/vectors-v1.json.\n"
                "Run from the repository root, or pass the path as argv[1] / $PS4RF_VECTORS.\n");
        return 2;
    }
    cat = jval_parse(buf, blen);
    if (cat == NULL || jval_kind(cat) != JVAL_OBJECT) {
        fprintf(stderr, "test_jcs: catalog parse failed\n");
        jval_free(cat);
        free(buf);
        return 2;
    }
    PASS("meta: catalog loaded (%zu bytes) and parsed", blen);

    test_appendix_b(cat);
    test_sample(cat);
    test_protocol_object(cat, "hello", hello_json, "hello_canonical_hex");
    test_protocol_object(cat, "hello_ack", hello_ack_json, "hello_ack_canonical_hex");

    test_boundary_ok(cat, "canonical_int_2p53_minus_1_ok", "[9007199254740991]");
    test_boundary_ok(cat, "canonical_float_neg_zero", "[-0.0]");
    test_boundary_ok(cat, "canonical_float_4_5_ok", "[4.5]");
    test_boundary_raises_text(cat, "canonical_int_2p53", "9007199254740992");
    test_boundary_raises_text(cat, "canonical_int_minus_2p53", "-9007199254740992");
    test_boundary_raises_text(cat, "canonical_float_integer_valued_1e30", "1e30");
    test_boundary_raises_text(cat, "canonical_float_nan", "NaN");
    test_boundary_raises_text(cat, "canonical_float_inf", "Infinity");
    test_boundary_raises_text(cat, "canonical_float_inf", "1e999");
    test_boundary_raises_value(cat, "canonical_float_nan", wb_new_double((double)NAN), "NaN value");
    test_boundary_raises_value(cat, "canonical_float_inf", wb_new_double((double)INFINITY), "+Infinity value");
    test_boundary_raises_value(cat, "canonical_float_inf", wb_new_double(-(double)INFINITY), "-Infinity value");
    test_nonstring_key(cat);

    test_key_order();
    test_escapes();
    test_literals();
    test_builder_api();
    test_syntax_rejects();
    test_formatter_edges();

    jval_free(cat);
    free(buf);

    printf("== %d checks passed, %d failed ==\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
