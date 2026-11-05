/* PS4RF P4/W8 -- shared shims used by BOTH builds so the dispatch logic behaves
 * identically on the console and on the host.
 *
 *   ps4rf_qsort   -- deterministic insertion sort (libPS4 has no qsort). Used through
 *                    `#define qsort ps4rf_qsort` in both builds: the canonical
 *                    serialization order must not depend on the C library.
 *   ps4rf_strtod  -- decimal -> double for the frozen JSON parser. libPS4 has no
 *                    strtod; the host build keeps its C library version, but the
 *                    *live* W8 message set contains no floating point value (the
 *                    generated operation table has no "double" argument), so this
 *                    path is not exercised on the wire. The host-side parity suite
 *                    remains the authority for float handling.
 */
#ifndef PS4RF_SHIM_H
#define PS4RF_SHIM_H

#include <stddef.h>
#include <stdint.h>

void ps4rf_qsort(void *base, size_t nmemb, size_t size,
                 int (*cmp)(const void *, const void *));
double ps4rf_strtod(const char *text, char **end);

#endif /* PS4RF_SHIM_H */
