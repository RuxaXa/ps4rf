/* PS4RF W8 compat: freestanding <math.h> for the libPS4 build.
 * Only the two things the frozen JSON parser needs; GCC builtins keep glibc's math.h
 * (and its conflicting `ceil` prototype) out of the payload. */
#ifndef PS4RF_COMPAT_MATH_H
#define PS4RF_COMPAT_MATH_H
#define INFINITY (__builtin_inff())
#define NAN (__builtin_nanf(""))
#define isfinite(x) __builtin_isfinite(x)
#define isnan(x) __builtin_isnan(x)
#endif /* PS4RF_COMPAT_MATH_H */
