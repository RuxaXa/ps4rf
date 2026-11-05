/* PS4RF W8 compat: <stdio.h> for the libPS4 build.
 * The agent never writes to stdout on the console; the frozen sources only need
 * snprintf (libPS4 pointer, filled by initLibc). */
#ifndef PS4RF_COMPAT_STDIO_H
#define PS4RF_COMPAT_STDIO_H
#include <stdarg.h>
#include "libc.h"
#endif
