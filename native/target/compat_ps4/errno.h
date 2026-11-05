/* PS4RF W8 compat: <errno.h> for the libPS4 build (kernel.h defines errno via __error()). */
#ifndef PS4RF_COMPAT_ERRNO_H
#define PS4RF_COMPAT_ERRNO_H
#include "kernel.h"
#ifndef EINTR
#define EINTR 4
#endif
#endif
