/*
 * ps4rf/native/src/jcs.c
 *
 * RFC 8785 (JCS) canonicalization, minimal JSON parser, ES6 number
 * formatting and the PS4RF safe-number policy layer for the native agent.
 * See jcs.h for the contract and semantics. C99, libc only.
 */

#include "jcs.h"

#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PS4RF_JCS_SAFE_MAX   INT64_C(9007199254740991)     /* 2^53 - 1 */
#define PS4RF_JCS_SAFE_MAX_D 9007199254740991.0            /* 2^53 - 1 exact */
#define PS4RF_JCS_MAX_DEPTH  1000u

/* ------------------------------------------------------------------ */
/* UTF-8 helpers                                                       */
/* ------------------------------------------------------------------ */

/* Decode one UTF-8 sequence (strict: rejects overlongs, surrogates,
 * values > U+10FFFF and lone continuation bytes). 0 ok, -1 invalid. */
static int utf8_decode(const unsigned char *s, size_t len, uint32_t *cp, size_t *n)
{
    if (len == 0) return -1;
    if (s[0] < 0x80) { *cp = s[0]; *n = 1; return 0; }
    if (s[0] < 0xC2 || s[0] > 0xF4) return -1;
    if (s[0] < 0xE0) {                                /* 2 bytes: C2..DF */
        if (len < 2 || (s[1] & 0xC0) != 0x80) return -1;
        *cp = ((uint32_t)(s[0] & 0x1Fu) << 6) | (uint32_t)(s[1] & 0x3Fu);
        *n = 2;
        return 0;
    }
    if (s[0] < 0xF0) {                                /* 3 bytes: E0..EF */
        if (len < 3) return -1;
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return -1;
        if (s[0] == 0xE0 && s[1] < 0xA0) return -1;   /* overlong */
        if (s[0] == 0xED && s[1] > 0x9F) return -1;   /* surrogate range */
        *cp = ((uint32_t)(s[0] & 0x0Fu) << 12) | ((uint32_t)(s[1] & 0x3Fu) << 6) |
              (uint32_t)(s[2] & 0x3Fu);
        *n = 3;
        return 0;
    }
    /* 4 bytes: F0..F4 */
    if (len < 4) return -1;
    if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return -1;
    if (s[0] == 0xF0 && s[1] < 0x90) return -1;       /* overlong */
    if (s[0] == 0xF4 && s[1] > 0x8F) return -1;       /* > U+10FFFF */
    *cp = ((uint32_t)(s[0] & 0x07u) << 18) | ((uint32_t)(s[1] & 0x3Fu) << 12) |
          ((uint32_t)(s[2] & 0x3Fu) << 6) | (uint32_t)(s[3] & 0x3Fu);
    *n = 4;
    return 0;
}

/* Encode one code point as UTF-8; returns 1..4 bytes written to out[4]. */
static size_t utf8_encode(uint32_t cp, char *out)
{
    if (cp < 0x80u) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800u) {
        out[0] = (char)(0xC0u | (cp >> 6));
        out[1] = (char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp < 0x10000u) {
        out[0] = (char)(0xE0u | (cp >> 12));
        out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    out[0] = (char)(0xF0u | (cp >> 18));
    out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (cp & 0x3Fu));
    return 4;
}

/* ------------------------------------------------------------------ */
/* jval lifecycle                                                      */
/* ------------------------------------------------------------------ */

static jval *jval_alloc(jval_type type)
{
    jval *v = (jval *)malloc(sizeof *v);
    if (v != NULL) {
        memset(v, 0, sizeof *v);
        v->type = type;
    }
    return v;
}

/* internal constructor used by the parser and jval_new_string */
static jval *jval_new_string_len(const char *bytes, size_t n);

/* Copy n bytes from p into a fresh NUL-terminated buffer; NULL on OOM. */
static char *dup_bytes(const char *p, size_t n)
{
    char *q = (char *)malloc(n + 1);
    if (q == NULL) return NULL;
    if (n != 0) memcpy(q, p, n);
    q[n] = '\0';
    return q;
}

jval *jval_new_null(void)
{
    return jval_alloc(JVAL_NULL);
}

jval *jval_new_bool(int v)
{
    jval *j = jval_alloc(JVAL_BOOL);
    if (j != NULL) j->u.b = (v != 0);
    return j;
}

jval *jval_new_int(int64_t v)
{
    jval *j = jval_alloc(JVAL_INT);
    if (j != NULL) j->u.i = v;
    return j;
}

jval *jval_new_object(void)
{
    return jval_alloc(JVAL_OBJECT);
}

jval *jval_new_array(void)
{
    return jval_alloc(JVAL_ARRAY);
}

jval *jval_new_string(const char *utf8)
{
    if (utf8 == NULL) return NULL;
    return jval_new_string_len(utf8, strlen(utf8));
}

/* internal: copies n bytes of UTF-8 */
static jval *jval_new_string_len(const char *bytes, size_t n)
{
    jval *j = jval_alloc(JVAL_STRING);
    if (j == NULL) return NULL;
    j->u.s.ptr = dup_bytes(bytes, n);
    if (j->u.s.ptr == NULL) {
        free(j);
        return NULL;
    }
    j->u.s.len = n;
    return j;
}

void jval_free(jval *v)
{
    if (v == NULL) return;
    switch (v->type) {
    case JVAL_STRING:
        free(v->u.s.ptr);
        break;
    case JVAL_ARRAY: {
        size_t i;
        for (i = 0; i < v->u.a.n; i++) jval_free(v->u.a.elem[i]);
        free(v->u.a.elem);
        break;
    }
    case JVAL_OBJECT: {
        size_t i;
        for (i = 0; i < v->u.o.n; i++) {
            free(v->u.o.m[i].key);
            jval_free(v->u.o.m[i].val);
        }
        free(v->u.o.m);
        break;
    }
    default:
        break;
    }
    free(v);
}

/* Append/replace by exact key bytes (Python dict semantics). Takes
 * ownership of value on success; on failure the caller keeps it. */
static int obj_set_key(jval *obj, const char *key, size_t klen, jval *value)
{
    size_t i;
    jmemb *m;
    for (i = 0; i < obj->u.o.n; i++) {
        m = &obj->u.o.m[i];
        if (m->klen == klen && memcmp(m->key, key, klen) == 0) {
            jval_free(m->val);
            m->val = value;
            return 0;
        }
    }
    if (obj->u.o.n == obj->u.o.cap) {
        size_t ncap = obj->u.o.cap == 0 ? 8 : obj->u.o.cap * 2;
        jmemb *nm = (jmemb *)realloc(obj->u.o.m, ncap * sizeof *nm);
        if (nm == NULL) return -1;
        obj->u.o.m = nm;
        obj->u.o.cap = ncap;
    }
    m = &obj->u.o.m[obj->u.o.n];
    m->key = dup_bytes(key, klen);
    if (m->key == NULL) return -1;
    m->klen = klen;
    m->val = value;
    obj->u.o.n++;
    return 0;
}

int jval_obj_set(jval *obj, const char *key, jval *value)
{
    if (obj == NULL || obj->type != JVAL_OBJECT || key == NULL || value == NULL) return -1;
    return obj_set_key(obj, key, strlen(key), value);
}

int jval_arr_add(jval *arr, jval *value)
{
    if (arr == NULL || arr->type != JVAL_ARRAY || value == NULL) return -1;
    if (arr->u.a.n == arr->u.a.cap) {
        size_t ncap = arr->u.a.cap == 0 ? 8 : arr->u.a.cap * 2;
        jval **ne = (jval **)realloc(arr->u.a.elem, ncap * sizeof *ne);
        if (ne == NULL) return -1;
        arr->u.a.elem = ne;
        arr->u.a.cap = ncap;
    }
    arr->u.a.elem[arr->u.a.n++] = value;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Accessors                                                           */
/* ------------------------------------------------------------------ */

jval_type jval_kind(const jval *v)
{
    return v == NULL ? JVAL_NULL : v->type;
}

size_t jval_count(const jval *v)
{
    if (v == NULL) return 0;
    if (v->type == JVAL_ARRAY) return v->u.a.n;
    if (v->type == JVAL_OBJECT) return v->u.o.n;
    return 0;
}

const jval *jval_at(const jval *v, size_t i)
{
    if (v == NULL) return NULL;
    if (v->type == JVAL_ARRAY) return i < v->u.a.n ? v->u.a.elem[i] : NULL;
    if (v->type == JVAL_OBJECT) return i < v->u.o.n ? v->u.o.m[i].val : NULL;
    return NULL;
}

const char *jval_key_at(const jval *obj, size_t i)
{
    if (obj == NULL || obj->type != JVAL_OBJECT || i >= obj->u.o.n) return NULL;
    return obj->u.o.m[i].key;
}

const jval *jval_get(const jval *obj, const char *key)
{
    size_t klen, i;
    if (obj == NULL || key == NULL || obj->type != JVAL_OBJECT) return NULL;
    klen = strlen(key);
    for (i = 0; i < obj->u.o.n; i++) {
        const jmemb *m = &obj->u.o.m[i];
        if (m->key != NULL && m->klen == klen && memcmp(m->key, key, klen) == 0) return m->val;
    }
    return NULL;
}

int jval_bool(const jval *v)
{
    return (v != NULL && v->type == JVAL_BOOL) ? v->u.b : 0;
}

int64_t jval_int(const jval *v)
{
    return (v != NULL && v->type == JVAL_INT) ? v->u.i : 0;
}

double jval_double(const jval *v)
{
    if (v == NULL) return 0.0;
    if (v->type == JVAL_DOUBLE) return v->u.d;
    if (v->type == JVAL_INT) return (double)v->u.i;
    return 0.0;
}

const char *jval_string(const jval *v, size_t *len)
{
    if (v == NULL || v->type != JVAL_STRING) {
        if (len != NULL) *len = 0;
        return NULL;
    }
    if (len != NULL) *len = v->u.s.len;
    return v->u.s.ptr;
}

/* ------------------------------------------------------------------ */
/* Parser (RFC 8259 grammar; see jcs.h for documented extensions)      */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *p;
    size_t len;
    size_t pos;
} pctx;

static void skip_ws(pctx *c)
{
    while (c->pos < c->len) {
        char ch = c->p[c->pos];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') c->pos++;
        else break;
    }
}

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Consume exactly four hex digits into *out. */
static int parse_u4(pctx *c, unsigned *out)
{
    unsigned v = 0;
    int i;
    if (c->len - c->pos < 4) return -1;
    for (i = 0; i < 4; i++) {
        int h = hexval(c->p[c->pos + (size_t)i]);
        if (h < 0) return -1;
        v = (v << 4) | (unsigned)h;
    }
    c->pos += 4;
    *out = v;
    return 0;
}

/* Growable byte buffer used while decoding string literals. */
static int buf_reserve(char **buf, size_t *cap, size_t need)
{
    char *nb;
    size_t ncap;
    if (need <= *cap) return 0;
    ncap = *cap;
    while (ncap < need) {
        if (ncap > ((size_t)-1) / 2) return -1;
        ncap *= 2;
    }
    nb = (char *)realloc(*buf, ncap);
    if (nb == NULL) return -1;
    *buf = nb;
    *cap = ncap;
    return 0;
}

static int buf_push(char **buf, size_t *cap, size_t *len, const char *src, size_t n)
{
    if (buf_reserve(buf, cap, *len + n) != 0) return -1;
    if (n != 0) memcpy(*buf + *len, src, n);
    *len += n;
    return 0;
}

/* Parse a string literal (cursor on the opening quote). */
static jval *parse_string(pctx *c)
{
    size_t cap = 32, len = 0;
    char *buf;

    c->pos++; /* opening quote, caller checked */
    buf = (char *)malloc(cap);
    if (buf == NULL) return NULL;

    for (;;) {
        unsigned char ch;
        if (c->pos >= c->len) goto fail;
        ch = (unsigned char)c->p[c->pos];
        if (ch == '"') {
            c->pos++;
            break;
        }
        if (ch == '\\') {
            uint32_t cp;
            char enc[4];
            size_t n;
            c->pos++;
            if (c->pos >= c->len) goto fail;
            switch (c->p[c->pos++]) {
            case '"':  cp = (uint32_t)'"';  break;
            case '\\': cp = (uint32_t)'\\'; break;
            case '/':  cp = (uint32_t)'/';  break;
            case 'b':  cp = 0x08u; break;
            case 'f':  cp = 0x0Cu; break;
            case 'n':  cp = 0x0Au; break;
            case 'r':  cp = 0x0Du; break;
            case 't':  cp = 0x09u; break;
            case 'u': {
                unsigned hi;
                if (parse_u4(c, &hi) != 0) goto fail;
                if (hi >= 0xD800u && hi <= 0xDBFFu) {          /* high surrogate */
                    unsigned lo;
                    if (c->len - c->pos < 2 || c->p[c->pos] != '\\' || c->p[c->pos + 1] != 'u') goto fail;
                    c->pos += 2;
                    if (parse_u4(c, &lo) != 0) goto fail;
                    if (lo < 0xDC00u || lo > 0xDFFFu) goto fail;
                    cp = 0x10000u + ((uint32_t)(hi - 0xD800u) << 10) + (uint32_t)(lo - 0xDC00u);
                } else if (hi >= 0xDC00u && hi <= 0xDFFFu) {
                    goto fail;                                 /* lone low surrogate */
                } else {
                    cp = (uint32_t)hi;
                }
                break;
            }
            default:
                goto fail;
            }
            n = utf8_encode(cp, enc);
            if (buf_push(&buf, &cap, &len, enc, n) != 0) goto fail;
            continue;
        }
        if (ch < 0x20u) goto fail;                     /* raw control byte in string */
        if (ch < 0x80u) {
            if (buf_push(&buf, &cap, &len, (const char *)&ch, 1) != 0) goto fail;
            c->pos++;
            continue;
        }
        {
            uint32_t cp;
            size_t n;
            if (utf8_decode((const unsigned char *)c->p + c->pos, c->len - c->pos, &cp, &n) != 0) goto fail;
            if (buf_push(&buf, &cap, &len, c->p + c->pos, n) != 0) goto fail;
            c->pos += n;
        }
    }

    {
        jval *v;
        if (buf_reserve(&buf, &cap, len + 1) != 0) goto fail;
        buf[len] = '\0';                  /* exposed strings are NUL-terminated */
        v = jval_alloc(JVAL_STRING);
        if (v == NULL) goto fail;
        v->u.s.ptr = buf;                 /* take ownership of the scratch buffer */
        v->u.s.len = len;
        return v;
    }
fail:
    free(buf);
    return NULL;
}

/* Parse a number literal. Integer literals (no '.', no exponent) stay
 * integers with int64 saturation; everything else is a double. */
static jval *parse_number(pctx *c)
{
    size_t start = c->pos;
    int neg = 0, is_float = 0;

    if (c->p[c->pos] == '-') {
        neg = 1;
        c->pos++;
    }
    if (c->pos >= c->len) return NULL;
    if (c->p[c->pos] == '0') {
        c->pos++;
    } else if (c->p[c->pos] >= '1' && c->p[c->pos] <= '9') {
        while (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9') c->pos++;
    } else {
        return NULL;
    }
    if (c->pos < c->len && c->p[c->pos] == '.') {
        is_float = 1;
        c->pos++;
        if (c->pos >= c->len || c->p[c->pos] < '0' || c->p[c->pos] > '9') return NULL;
        while (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9') c->pos++;
    }
    if (c->pos < c->len && (c->p[c->pos] == 'e' || c->p[c->pos] == 'E')) {
        is_float = 1;
        c->pos++;
        if (c->pos < c->len && (c->p[c->pos] == '+' || c->p[c->pos] == '-')) c->pos++;
        if (c->pos >= c->len || c->p[c->pos] < '0' || c->p[c->pos] > '9') return NULL;
        while (c->pos < c->len && c->p[c->pos] >= '0' && c->p[c->pos] <= '9') c->pos++;
    }

    if (!is_float) {
        uint64_t acc = 0;
        uint64_t limit = neg ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
        int sat = 0;
        size_t i;
        jval *v;
        for (i = start + (size_t)(neg ? 1 : 0); i < c->pos; i++) {
            uint64_t d = (uint64_t)(c->p[i] - '0');
            if (!sat) {
                if (acc > (limit - d) / 10u) sat = 1;
                else acc = acc * 10u + d;
            }
        }
        v = jval_alloc(JVAL_INT);
        if (v == NULL) return NULL;
        if (sat) v->u.i = neg ? INT64_MIN : INT64_MAX;
        else if (neg) v->u.i = (acc == (uint64_t)INT64_MAX + 1u) ? INT64_MIN : -(int64_t)acc;
        else v->u.i = (int64_t)acc;
        return v;
    }

    {
        size_t tlen = c->pos - start;
        char *tmp = (char *)malloc(tlen + 1);
        double d;
        jval *v;
        if (tmp == NULL) return NULL;
        memcpy(tmp, c->p + start, tlen);
        tmp[tlen] = '\0';
        d = strtod(tmp, NULL);
        free(tmp);
        v = jval_alloc(JVAL_DOUBLE);
        if (v == NULL) return NULL;
        v->u.d = d;
        return v;
    }
}

static jval *parse_value(pctx *c, unsigned depth);

static jval *parse_array(pctx *c, unsigned depth)
{
    jval *arr = jval_new_array();
    if (arr == NULL) return NULL;
    c->pos++; /* '[' */
    skip_ws(c);
    if (c->pos < c->len && c->p[c->pos] == ']') {
        c->pos++;
        return arr;
    }
    for (;;) {
        jval *v;
        skip_ws(c);
        v = parse_value(c, depth + 1);
        if (v == NULL) goto fail;
        if (jval_arr_add(arr, v) != 0) {
            jval_free(v);
            goto fail;
        }
        skip_ws(c);
        if (c->pos >= c->len) goto fail;
        if (c->p[c->pos] == ',') {
            c->pos++;
            continue;
        }
        if (c->p[c->pos] == ']') {
            c->pos++;
            return arr;
        }
        goto fail;
    }
fail:
    jval_free(arr);
    return NULL;
}

static jval *parse_object(pctx *c, unsigned depth)
{
    jval *obj = jval_new_object();
    if (obj == NULL) return NULL;
    c->pos++; /* '{' */
    skip_ws(c);
    if (c->pos < c->len && c->p[c->pos] == '}') {
        c->pos++;
        return obj;
    }
    for (;;) {
        jval *k, *v;
        skip_ws(c);
        if (c->pos >= c->len || c->p[c->pos] != '"') goto fail;
        k = parse_string(c);
        if (k == NULL) goto fail;
        skip_ws(c);
        if (c->pos >= c->len || c->p[c->pos] != ':') {
            jval_free(k);
            goto fail;
        }
        c->pos++;
        skip_ws(c);
        v = parse_value(c, depth + 1);
        if (v == NULL) {
            jval_free(k);
            goto fail;
        }
        if (obj_set_key(obj, k->u.s.ptr, k->u.s.len, v) != 0) {
            jval_free(k);
            jval_free(v);
            goto fail;
        }
        jval_free(k);
        skip_ws(c);
        if (c->pos >= c->len) goto fail;
        if (c->p[c->pos] == ',') {
            c->pos++;
            continue;
        }
        if (c->p[c->pos] == '}') {
            c->pos++;
            return obj;
        }
        goto fail;
    }
fail:
    jval_free(obj);
    return NULL;
}

static jval *parse_value(pctx *c, unsigned depth)
{
    char ch;
    if (depth > PS4RF_JCS_MAX_DEPTH) return NULL;
    if (c->pos >= c->len) return NULL;
    ch = c->p[c->pos];
    switch (ch) {
    case '{':
        return parse_object(c, depth);
    case '[':
        return parse_array(c, depth);
    case '"':
        return parse_string(c);
    case 't':
        if (c->len - c->pos >= 4 && memcmp(c->p + c->pos, "true", 4) == 0) {
            c->pos += 4;
            return jval_new_bool(1);
        }
        return NULL;
    case 'f':
        if (c->len - c->pos >= 5 && memcmp(c->p + c->pos, "false", 5) == 0) {
            c->pos += 5;
            return jval_new_bool(0);
        }
        return NULL;
    case 'n':
        if (c->len - c->pos >= 4 && memcmp(c->p + c->pos, "null", 4) == 0) {
            c->pos += 4;
            return jval_new_null();
        }
        return NULL;
    case 'N': { /* CPython json extension: non-finite literals */
        jval *v;
        if (c->len - c->pos < 3 || memcmp(c->p + c->pos, "NaN", 3) != 0) return NULL;
        c->pos += 3;
        v = jval_alloc(JVAL_DOUBLE);
        if (v != NULL) v->u.d = (double)NAN;
        return v;
    }
    case 'I': {
        jval *v;
        if (c->len - c->pos < 8 || memcmp(c->p + c->pos, "Infinity", 8) != 0) return NULL;
        c->pos += 8;
        v = jval_alloc(JVAL_DOUBLE);
        if (v != NULL) v->u.d = (double)INFINITY;
        return v;
    }
    case '-':
        if (c->len - c->pos >= 9 && memcmp(c->p + c->pos, "-Infinity", 9) == 0) {
            jval *v;
            c->pos += 9;
            v = jval_alloc(JVAL_DOUBLE);
            if (v != NULL) v->u.d = -(double)INFINITY;
            return v;
        }
        return parse_number(c);
    default:
        if (ch >= '0' && ch <= '9') return parse_number(c);
        return NULL;
    }
}

jval *jval_parse(const char *text, size_t len)
{
    pctx c;
    jval *v;
    if (text == NULL) return NULL;
    c.p = text;
    c.len = len;
    c.pos = 0;
    skip_ws(&c);
    v = parse_value(&c, 0);
    if (v == NULL) return NULL;
    skip_ws(&c);
    if (c.pos != c.len) {
        jval_free(v);
        return NULL;
    }
    return v;
}

/* ------------------------------------------------------------------ */
/* UTF-16 key ordering (RFC 8785 3.2.3)                                */
/* ------------------------------------------------------------------ */

/* Compare two keys by their UTF-16 code-unit sequences. Invalid UTF-8 is
 * handled deterministically (each bad byte sorts as U+FFFD). */
static int utf16_key_cmp(const char *a, size_t alen, const char *b, size_t blen)
{
    size_t ia = 0, ib = 0;
    for (;;) {
        uint32_t ca, cb, fa, fb;
        size_t na, nb;
        if (ia >= alen && ib >= blen) return 0;
        if (ia >= alen) return -1;
        if (ib >= blen) return 1;
        if (utf8_decode((const unsigned char *)a + ia, alen - ia, &ca, &na) != 0) {
            ca = 0xFFFDu;
            na = 1;
        }
        if (utf8_decode((const unsigned char *)b + ib, blen - ib, &cb, &nb) != 0) {
            cb = 0xFFFDu;
            nb = 1;
        }
        if (ca != cb) {
            /* First UTF-16 code unit: astral characters map into the
             * surrogate range D800..DBFF, which is what makes them sort
             * before BMP characters >= U+E000. */
            fa = ca < 0x10000u ? ca : 0xD800u + ((ca - 0x10000u) >> 10);
            fb = cb < 0x10000u ? cb : 0xD800u + ((cb - 0x10000u) >> 10);
            if (fa != fb) return fa < fb ? -1 : 1;
            /* Equal first unit with different code points: both are
             * astral with the same high 10 bits; the order is then the
             * numeric code point order (i.e. the low surrogate unit). */
            return ca < cb ? -1 : 1;
        }
        ia += na;
        ib += nb;
    }
}

/* ------------------------------------------------------------------ */
/* Serializer                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    char *p;
    size_t len;
    size_t cap;
} sbuf;

static int sb_grow(sbuf *s, size_t extra)
{
    size_t need, ncap;
    char *np;
    if (extra > (size_t)-1 - s->len - 1u) return -1;
    need = s->len + extra + 1u; /* keep room for the trailing NUL */
    if (need <= s->cap) return 0;
    ncap = s->cap == 0 ? 64 : s->cap;
    while (ncap < need) {
        if (ncap > (size_t)-1 / 2u) {
            ncap = need;
            break;
        }
        ncap *= 2;
    }
    np = (char *)realloc(s->p, ncap);
    if (np == NULL) return -1;
    s->p = np;
    s->cap = ncap;
    return 0;
}

static int sb_raw(sbuf *s, const char *data, size_t n)
{
    if (sb_grow(s, n) != 0) return -1;
    if (n != 0) memcpy(s->p + s->len, data, n);
    s->len += n;
    return 0;
}

static int sb_str(sbuf *s, const char *z)
{
    return sb_raw(s, z, strlen(z));
}

static int sb_ch(sbuf *s, char ch)
{
    return sb_raw(s, &ch, 1);
}

/* JSON string per RFC 8785 3.2.2.2: quote, backslash, and C0 controls are
 * escaped; \b \f \n \r \t use short forms, other C0 controls \u00xx
 * (lowercase hex); everything else (including DEL, non-ASCII UTF-8) is
 * emitted verbatim. */
static int sb_json_string(sbuf *s, const char *str, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;
    if (sb_ch(s, '"') != 0) return -1;
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)str[i];
        switch (ch) {
        case '"':
            if (sb_str(s, "\\\"") != 0) return -1;
            break;
        case '\\':
            if (sb_str(s, "\\\\") != 0) return -1;
            break;
        case '\b':
            if (sb_str(s, "\\b") != 0) return -1;
            break;
        case '\f':
            if (sb_str(s, "\\f") != 0) return -1;
            break;
        case '\n':
            if (sb_str(s, "\\n") != 0) return -1;
            break;
        case '\r':
            if (sb_str(s, "\\r") != 0) return -1;
            break;
        case '\t':
            if (sb_str(s, "\\t") != 0) return -1;
            break;
        default:
            if (ch < 0x20u) {
                char esc[6];
                esc[0] = '\\';
                esc[1] = 'u';
                esc[2] = '0';
                esc[3] = '0';
                esc[4] = hexd[(ch >> 4) & 0x0Fu];
                esc[5] = hexd[ch & 0x0Fu];
                if (sb_raw(s, esc, 6) != 0) return -1;
            } else if (sb_ch(s, (char)ch) != 0) {
                return -1;
            }
            break;
        }
    }
    return sb_ch(s, '"');
}

static int cmp_jmemb_ptr(const void *pa, const void *pb)
{
    const jmemb *a = *(const jmemb *const *)pa;
    const jmemb *b = *(const jmemb *const *)pb;
    return utf16_key_cmp(a->key == NULL ? "" : a->key, a->key == NULL ? 0 : a->klen,
                         b->key == NULL ? "" : b->key, b->key == NULL ? 0 : b->klen);
}

static int write_value(sbuf *s, const jval *v, unsigned depth)
{
    if (v == NULL || depth > PS4RF_JCS_MAX_DEPTH) return -1;
    switch (v->type) {
    case JVAL_NULL:
        return sb_str(s, "null");
    case JVAL_BOOL:
        return sb_str(s, v->u.b ? "true" : "false");
    case JVAL_INT: {
        char tmp[32];
        int n;
        if (v->u.i < -PS4RF_JCS_SAFE_MAX || v->u.i > PS4RF_JCS_SAFE_MAX) return -1;
        n = snprintf(tmp, sizeof tmp, "%lld", (long long)v->u.i);
        if (n < 0 || (size_t)n >= sizeof tmp) return -1;
        return sb_raw(s, tmp, (size_t)n);
    }
    case JVAL_DOUBLE: {
        char tmp[32];
        if (jcs_format_double(v->u.d, tmp, sizeof tmp) != 0) return -1;
        return sb_str(s, tmp);
    }
    case JVAL_STRING:
        return sb_json_string(s, v->u.s.ptr, v->u.s.len);
    case JVAL_ARRAY: {
        size_t i;
        if (sb_ch(s, '[') != 0) return -1;
        for (i = 0; i < v->u.a.n; i++) {
            if (i != 0 && sb_ch(s, ',') != 0) return -1;
            if (write_value(s, v->u.a.elem[i], depth + 1) != 0) return -1;
        }
        return sb_ch(s, ']');
    }
    case JVAL_OBJECT: {
        size_t i;
        if (v->u.o.n == 0) return sb_str(s, "{}");
        {
            jmemb **ord = (jmemb **)malloc(v->u.o.n * sizeof *ord);
            if (ord == NULL) return -1;
            for (i = 0; i < v->u.o.n; i++) ord[i] = &v->u.o.m[i];
            qsort(ord, v->u.o.n, sizeof *ord, cmp_jmemb_ptr);
            if (sb_ch(s, '{') != 0) {
                free(ord);
                return -1;
            }
            for (i = 0; i < v->u.o.n; i++) {
                const jmemb *m = ord[i];
                if (i != 0 && sb_ch(s, ',') != 0) {
                    free(ord);
                    return -1;
                }
                if (sb_json_string(s, m->key == NULL ? "" : m->key, m->key == NULL ? 0 : m->klen) != 0 ||
                    sb_ch(s, ':') != 0 ||
                    write_value(s, m->val, depth + 1) != 0) {
                    free(ord);
                    return -1;
                }
            }
            free(ord);
        }
        return sb_ch(s, '}');
    }
    default:
        return -1;
    }
}

int jcs_serialize(const jval *v, char **out, size_t *out_len)
{
    sbuf s;
    if (out == NULL || out_len == NULL) return -1;
    *out = NULL;
    *out_len = 0;
    if (v == NULL) return -1;
    s.p = NULL;
    s.len = 0;
    s.cap = 0;
    if (write_value(&s, v, 0) != 0) {
        free(s.p);
        return -1;
    }
    if (sb_grow(&s, 0) != 0) {
        free(s.p);
        return -1;
    }
    s.p[s.len] = '\0';
    *out = s.p;
    *out_len = s.len;
    return 0;
}

int jcs_serialize_text(const char *text, size_t len, char **out, size_t *out_len)
{
    jval *v;
    int rc;
    if (out != NULL) *out = NULL;
    if (out_len != NULL) *out_len = 0;
    v = jval_parse(text, len);
    if (v == NULL) return -1;
    rc = jcs_serialize(v, out, out_len);
    jval_free(v);
    return rc;
}

/* ------------------------------------------------------------------ */
/* ES6 / RFC 8785 number formatting                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    char *out;
    size_t cap;
    size_t n;
} dout;

static int dout_ch(dout *d, char ch)
{
    if (d->n + 1u >= d->cap) return -1; /* reserve room for the NUL */
    d->out[d->n++] = ch;
    return 0;
}

/*
 * ECMAScript Number::toString (ECMA-262 7.1.12.1), as amended by RFC 8785
 * 3.2.2.3:
 *   - format v with %.*e at increasing precision (1..17 significant
 *     digits) until reading it back with strtod() yields the exact same
 *     double; glibc is correctly rounded, so the first precision that
 *     round-trips carries the shortest digit string;
 *   - take s = the digits (trailing zeros stripped), k = digit count,
 *     n = decimal exponent position (value = s * 10^(n-k));
 *   - k <= n <= 21: digits followed by n-k zeros ("integer form");
 *     0 < n <= 21: digits with the point after n digits;
 *     -6 < n <= 0: "0." then -n zeros then digits;
 *     otherwise exponential: digit(s) + "e" + sign + |n-1|, no padding,
 *     '+' for non-negative exponents, '-' for negative ones;
 *   - negative zero prints "0"; NaN/Infinity are errors (-1).
 */
int jcs_format_double(double v, char *out, size_t cap)
{
    static const char fmt_e[] = "%.*e";
    char ebuf[64], digits[24];
    dout d;
    double av;
    long k, n;
    int neg, p, found = 0;
    const char *eptr;
    size_t i;

    if (out == NULL || cap < 2) return -1;
    if (!(v == v) || v > DBL_MAX || v < -DBL_MAX) return -1; /* NaN / +-Inf */
    if (v == 0.0) {                                          /* covers -0.0 */
        out[0] = '0';
        out[1] = '\0';
        return 0;
    }

    neg = v < 0.0;
    av = neg ? -v : v;

    for (p = 1; p <= 17; p++) {
        int m = snprintf(ebuf, sizeof ebuf, fmt_e, p - 1, av);
        if (m < 0 || (size_t)m >= sizeof ebuf) return -1;
        if (strtod(ebuf, NULL) == av) {
            found = 1;
            break;
        }
    }
    if (!found) return -1;

    eptr = strchr(ebuf, 'e');
    if (eptr == NULL) return -1;
    {
        long exp10 = strtol(eptr + 1, NULL, 10);
        size_t kk = 0;
        const char *q;
        for (q = ebuf; q < eptr; q++) {
            if (*q >= '0' && *q <= '9') {
                if (kk >= sizeof digits) return -1;
                digits[kk++] = *q;
            }
        }
        if (kk == 0 || kk > 17) return -1;
        while (kk > 1 && digits[kk - 1] == '0') kk--;
        k = (long)kk;
        n = exp10 + 1;
    }

    d.out = out;
    d.cap = cap;
    d.n = 0;
    if (neg && dout_ch(&d, '-') != 0) return -1;

    if (k <= n && n <= 21) {
        for (i = 0; i < (size_t)k; i++)
            if (dout_ch(&d, digits[i]) != 0) return -1;
        for (i = 0; i < (size_t)(n - k); i++)
            if (dout_ch(&d, '0') != 0) return -1;
    } else if (n > 0 && n <= 21) {
        for (i = 0; i < (size_t)n; i++)
            if (dout_ch(&d, digits[i]) != 0) return -1;
        if (dout_ch(&d, '.') != 0) return -1;
        for (i = (size_t)n; i < (size_t)k; i++)
            if (dout_ch(&d, digits[i]) != 0) return -1;
    } else if (n > -6 && n <= 0) {
        if (dout_ch(&d, '0') != 0 || dout_ch(&d, '.') != 0) return -1;
        for (i = 0; i < (size_t)(-n); i++)
            if (dout_ch(&d, '0') != 0) return -1;
        for (i = 0; i < (size_t)k; i++)
            if (dout_ch(&d, digits[i]) != 0) return -1;
    } else {
        long ex = n - 1;
        unsigned long ax = (unsigned long)(ex < 0 ? -ex : ex);
        char tmp[8];
        int t = 0;
        if (dout_ch(&d, digits[0]) != 0) return -1;
        if (k > 1) {
            if (dout_ch(&d, '.') != 0) return -1;
            for (i = 1; i < (size_t)k; i++)
                if (dout_ch(&d, digits[i]) != 0) return -1;
        }
        if (dout_ch(&d, 'e') != 0) return -1;
        if (dout_ch(&d, ex < 0 ? '-' : '+') != 0) return -1;
        do {
            tmp[t++] = (char)('0' + (ax % 10u));
            ax /= 10u;
        } while (ax != 0);
        while (t > 0) {
            t--;
            if (dout_ch(&d, tmp[t]) != 0) return -1;
        }
    }

    d.out[d.n] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* PS4RF safe-number policy (mirrors core/canonical.py)                */
/* ------------------------------------------------------------------ */

static int check_safe(const jval *v, const char **errname)
{
    size_t i;
    if (v == NULL) {
        *errname = "TypeError";
        return -1;
    }
    switch (v->type) {
    case JVAL_NULL:
    case JVAL_BOOL:
    case JVAL_STRING:
        return 0;
    case JVAL_INT:
        /* Python: SAFE_MIN <= obj <= SAFE_MAX for int, else UnsafeNumber. */
        if (v->u.i < -PS4RF_JCS_SAFE_MAX || v->u.i > PS4RF_JCS_SAFE_MAX) {
            *errname = "UnsafeNumber";
            return -1;
        }
        return 0;
    case JVAL_DOUBLE:
        /* Python: not finite -> UnsafeNumber; is_integer() and abs > max
         * -> UnsafeNumber. At |x| > 2^52 every double is an integer and
         * SAFE_MAX = 2^53-1 >= 2^52, so the conjunction reduces to the
         * range test. */
        if (!isfinite(v->u.d)) {
            *errname = "UnsafeNumber";
            return -1;
        }
        if (v->u.d < -PS4RF_JCS_SAFE_MAX_D || v->u.d > PS4RF_JCS_SAFE_MAX_D) {
            *errname = "UnsafeNumber";
            return -1;
        }
        return 0;
    case JVAL_ARRAY:
        for (i = 0; i < v->u.a.n; i++) {
            if (check_safe(v->u.a.elem[i], errname) != 0) return -1;
        }
        return 0;
    case JVAL_OBJECT:
        for (i = 0; i < v->u.o.n; i++) {
            if (v->u.o.m[i].key == NULL) { /* non-string key (builder misuse) */
                *errname = "TypeError";
                return -1;
            }
            if (check_safe(v->u.o.m[i].val, errname) != 0) return -1;
        }
        return 0;
    default:
        *errname = "TypeError";
        return -1;
    }
}

int ps4rf_canonical_bytes(const jval *v, char **out, size_t *out_len, const char **error_name)
{
    const char *name = NULL;
    if (out == NULL || out_len == NULL) return -1;
    *out = NULL;
    *out_len = 0;
    if (error_name != NULL) *error_name = NULL;
    if (check_safe(v, &name) != 0) {
        if (error_name != NULL) *error_name = name;
        return -1;
    }
    if (jcs_serialize(v, out, out_len) != 0) {
        if (error_name != NULL) *error_name = "MemoryError";
        return -1;
    }
    return 0;
}

int ps4rf_canonical_bytes_text(const char *text, size_t len, char **out, size_t *out_len, const char **error_name)
{
    jval *v;
    int rc;
    if (out == NULL || out_len == NULL) return -1;
    *out = NULL;
    *out_len = 0;
    if (error_name != NULL) *error_name = NULL;
    v = jval_parse(text, len);
    if (v == NULL) {
        if (error_name != NULL) *error_name = "SyntaxError";
        return -1;
    }
    rc = ps4rf_canonical_bytes(v, out, out_len, error_name);
    jval_free(v);
    return rc;
}
