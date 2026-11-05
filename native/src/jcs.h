/*
 * ps4rf/native/src/jcs.h
 *
 * RFC 8785 (JSON Canonicalization Scheme) for the PS4RF native agent:
 * a small self-contained JSON parser, the JCS serializer, ES6/RFC 8785
 * number formatting, and the PS4RF safe-number policy layer that mirrors
 * core/canonical.py (validate_safe_numbers + jcs serialization).
 *
 * Constraints (frozen):
 *   - C99, no external libraries (libc only), no network, no subprocess.
 *   - No locale calls. Everything runs in the default "C" locale, so
 *     printf/strtod use '.' as the decimal separator and glibc's
 *     correctly-rounded conversions back the ECMAScript Number::toString
 *     algorithm (shortest round-trip digits).
 *   - Byte-for-byte parity with the Python reference is the acceptance
 *     criterion; weaker checks are meaningless.
 *
 * Semantics beyond the declaration list:
 *   - jval_parse implements the RFC 8259 grammar plus the three non-finite
 *     literals "NaN", "Infinity", "-Infinity" that CPython's json module
 *     accepts (the PS4RF reference); the policy layer then refuses them
 *     with UnsafeNumber, exactly like the Python reference. RFC 8785
 *     output can never contain them.
 *   - Object keys are decoded UTF-8 byte strings; duplicate keys follow
 *     Python dict semantics (last occurrence wins, first position kept).
 *   - Integers larger than int64 saturate to INT64_MAX/INT64_MIN (they are
 *     far outside the safe-number domain and are rejected by the policy
 *     layer anyway). Float literals that overflow the double range become
 *     +/-infinity (CPython parity: float("1e999") == inf).
 *   - Unpaired surrogates and invalid UTF-8 in the input text are syntax
 *     errors (NULL). The Python reference accepts lone surrogates at parse
 *     time and then refuses to canonicalize them; both ends refuse.
 *   - Nesting depth is limited to 1000 levels (parse and serialize).
 *   - Strings passed to jval_new_string / jval_obj_set are trusted to be
 *     valid UTF-8; the serializer passes invalid byte sequences through
 *     byte-wise (no divergence risk on the wire path, which is validated).
 *   - jcs_serialize mirrors the rfc8785 Python package: a non-finite
 *     double or an integer outside +/- (2^53 - 1) is an error (-1), like
 *     FloatDomainError / IntegerDomainError there.
 *   - *out from jcs_serialize / ps4rf_canonical_bytes* is malloc'd, NUL
 *     terminated, and must be released with free(). *out_len excludes the
 *     NUL.
 *   - error_name values: "UnsafeNumber" / "TypeError" for policy failures
 *     (per the frozen contract); "SyntaxError" for unparseable text and
 *     "MemoryError" for allocation failure are documented extensions.
 */
#ifndef PS4RF_JCS_H
#define PS4RF_JCS_H

#include <stddef.h>
#include <stdint.h>

typedef enum { JVAL_NULL, JVAL_BOOL, JVAL_INT, JVAL_DOUBLE, JVAL_STRING, JVAL_ARRAY, JVAL_OBJECT } jval_type;
typedef struct jval jval;

jval *jval_parse(const char *text, size_t len);            /* NULL on syntax error */
void  jval_free(jval *v);
jval_type jval_kind(const jval *v);
const jval *jval_get(const jval *obj, const char *key);    /* NULL if absent or not an object */
size_t jval_count(const jval *v);                          /* array length / object member count */
const jval *jval_at(const jval *v, size_t i);              /* array element or member value (any order for objects) */
const char *jval_key_at(const jval *obj, size_t i);        /* member key, NULL otherwise */
int     jval_bool(const jval *v);
int64_t jval_int(const jval *v);                           /* integer-valued JSON literal */
double  jval_double(const jval *v);                        /* any JSON number as double */
const char *jval_string(const jval *v, size_t *len);       /* NUL-terminated, decoding \uXXXX incl. surrogate pairs to UTF-8 */
jval *jval_new_object(void);
jval *jval_new_array(void);
jval *jval_new_string(const char *utf8);
jval *jval_new_int(int64_t v);
jval *jval_new_bool(int v);
jval *jval_new_null(void);
int   jval_obj_set(jval *obj, const char *key, jval *value); /* takes ownership of value; 0 ok */
int   jval_arr_add(jval *arr, jval *value);                  /* takes ownership; 0 ok */

/* RFC 8785 serialization of a parsed value: sorted keys, no whitespace, ES6 number formatting. 0 ok, -1 error */
int jcs_serialize(const jval *v, char **out, size_t *out_len);
int jcs_serialize_text(const char *text, size_t len, char **out, size_t *out_len);

/* ES6/RFC8785 number -> shortest decimal string (exposed for the appendix-B vectors) */
int jcs_format_double(double v, char *out, size_t cap);

/* PS4RF protocol policy layer, mirroring core/canonical.py validate_safe_numbers + jcs serialization.
   On failure returns -1 and sets *error_name to one of "UnsafeNumber" or "TypeError". */
int ps4rf_canonical_bytes(const jval *v, char **out, size_t *out_len, const char **error_name);
int ps4rf_canonical_bytes_text(const char *text, size_t len, char **out, size_t *out_len, const char **error_name);

/*
 * Internal value representation.
 *
 * Kept visible deliberately: this lets the self-test (native/tests/test_jcs.c)
 * exercise the policy layer's two cases the frozen builder API cannot express
 * (a NaN/Infinity double value, and a non-string object key) without widening
 * the contract, and lets embedders audit memory layout. Treat all fields as
 * read-only; mutate only through the functions above and release only with
 * jval_free().
 *
 * Layout notes:
 *   - JVAL_INT stores an int64_t; JVAL_DOUBLE stores the raw double.
 *   - JVAL_STRING: u.s.ptr is a NUL-terminated malloc'd buffer; u.s.len is
 *     the true byte length (embedded NULs are legal and preserved).
 *   - JVAL_ARRAY: u.a.elem[0..u.a.n) are owned jval pointers.
 *   - JVAL_OBJECT: u.o.m[0..u.o.n) members; key is a NUL-terminated malloc'd
 *     UTF-8 byte string, klen its true byte length, val an owned jval.
 *     A NULL key is the internal representation of a non-string key; the
 *     public builder API refuses to create one, and the policy layer maps
 *     it to TypeError.
 */
typedef struct jmemb { char *key; size_t klen; jval *val; } jmemb;

struct jval {
    jval_type type;
    union {
        int b;
        int64_t i;
        double d;
        struct { char *ptr; size_t len; } s;
        struct { jval **elem; size_t n; size_t cap; } a;
        struct { jmemb *m; size_t n; size_t cap; } o;
    } u;
};

#endif /* PS4RF_JCS_H */
