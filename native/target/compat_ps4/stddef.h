/* PS4RF W8 compat: freestanding <stddef.h> for the libPS4 build.
 * Reuses the SDK's types.h (size_t, NULL, the uintN aliases) instead of GCC's stddef.h,
 * whose wchar_t conflicts with the SDK's wchar_t definition. */
#ifndef PS4RF_COMPAT_STDDEF_H
#define PS4RF_COMPAT_STDDEF_H
#include <stdint.h>
#include "types.h"
#ifndef offsetof
#define offsetof(type, member) ((size_t)((char *)&((type *)0)->member - (char *)0))
#endif
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#endif /* PS4RF_COMPAT_STDDEF_H */
