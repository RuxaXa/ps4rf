/* PS4RF W8 compat: <stdlib.h> for the libPS4 build. qsort is absent from libPS4,
 * so the agent uses its own deterministic insertion sort (ps4rf_shim.c) in both the
 * payload and the host build -- identical ordering on both sides. */
#ifndef PS4RF_COMPAT_STDLIB_H
#define PS4RF_COMPAT_STDLIB_H
#include "libc.h"
#include "ps4rf_shim.h"
#define qsort ps4rf_qsort
#define strtod ps4rf_strtod
#endif
