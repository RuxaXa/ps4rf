/* PS4RF P4/W8 target agent -- shims (see ps4rf_shim.h). */
#include "ps4rf_shim.h"
#include "ps4rf_libc.h"

void ps4rf_qsort(void *base, size_t nmemb, size_t size,
                 int (*cmp)(const void *, const void *))
{
    /* Deterministic insertion sort over byte offsets: the only user is the canonical
     * serializer's key ordering, whose arrays stay small (one entry per object member). */
    size_t i;
    unsigned char *bytes = (unsigned char *)base;
    unsigned char tmp;
    size_t k;

    if (base == NULL || cmp == NULL || nmemb < 2u || size == 0u) return;
    for (i = 1u; i < nmemb; i++) {
        size_t j = i;
        while (j > 0u && cmp(bytes + (j - 1u) * size, bytes + j * size) > 0) {
            /* swap the two records byte-wise */
            unsigned char *a = bytes + (j - 1u) * size;
            unsigned char *b = bytes + j * size;
            for (k = 0u; k < size; k++) {
                tmp = a[k];
                a[k] = b[k];
                b[k] = tmp;
            }
            j--;
        }
    }
}

#ifdef PS4RF_TARGET_PS4
/* Not exercised by the W8 wire path (no floating point value in the live op set).
 * Kept deliberately small and documented rather than silently wrong: it accepts the
 * same grammar jcs.c feeds it (integer / fraction / exponent) and stops at the first
 * character it cannot consume. */
double ps4rf_strtod(const char *text, char **end)
{
    double value = 0.0;
    double scale = 1.0;
    int negative = 0;
    int any = 0;
    const char *p = text;

    if (p == NULL) {
        if (end != NULL) *end = (char *)text;
        return 0.0;
    }
    if (*p == '+' || *p == '-') {
        negative = (*p == '-');
        p++;
    }
    while (*p >= '0' && *p <= '9') {
        value = value * 10.0 + (double)(*p - '0');
        any = 1;
        p++;
    }
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            scale /= 10.0;
            value += (double)(*p - '0') * scale;
            any = 1;
            p++;
        }
    }
    if (any && (*p == 'e' || *p == 'E')) {
        const char *q = p + 1;
        int eneg = 0;
        int exp = 0;
        if (*q == '+' || *q == '-') {
            eneg = (*q == '-');
            q++;
        }
        if (*q >= '0' && *q <= '9') {
            while (*q >= '0' && *q <= '9') {
                if (exp < 100000) exp = exp * 10 + (int)(*q - '0');
                q++;
            }
            while (exp-- > 0) value = eneg ? (value / 10.0) : (value * 10.0);
            p = q;
        }
    }
    if (end != NULL) *end = (char *)p;
    return negative ? -value : value;
}
#endif /* PS4RF_TARGET_PS4 */
