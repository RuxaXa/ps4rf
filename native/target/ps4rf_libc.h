/* PS4RF P4/W8 target agent -- libc surface used by the platform-free modules.
 *
 * The agent modules (resources, evidence, telemetry, stub provider, router, session)
 * are compiled unchanged for two very different runtimes:
 *
 *   * the PS4 payload build  (libPS4: every libc entry point is a function pointer in
 *     .bss that ``initLibc`` fills, plus compiled-in syscall wrappers for open/read/
 *     write/close). PS4RF_TARGET_PS4 selects that surface.
 *   * the host build          (offline tests, the host controller loopback). Plain libc.
 *
 * Only this header knows the difference, so the dispatch logic that runs on the
 * console is byte-identical to the logic that is exercised on the host.
 */
#ifndef PS4RF_LIBC_H
#define PS4RF_LIBC_H

#ifdef PS4RF_TARGET_PS4

#include "ps4.h"          /* libPS4 umbrella: types.h, libc.h, network.h, kernel.h, ... */

/* libPS4 declares the libc entry points as pointers (extern void *(*memcpy)(...)).
 * The agent only needs the ones below to exist; initLibc fills them before _main
 * touches any of them. */
#define PS4RF_HAVE_SNPRINTF 1
#define PS4RF_HAVE_STRTOUL 0

#else /* host build */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PS4RF_HAVE_SNPRINTF 1
#define PS4RF_HAVE_STRTOUL 1

#endif /* PS4RF_TARGET_PS4 */

#endif /* PS4RF_LIBC_H */
