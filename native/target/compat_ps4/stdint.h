/* PS4RF W8 compat: freestanding <stdint.h> for the libPS4 build.
 * Deliberately self-contained (GCC type builtins only): pulling glibc's stdint.h into a
 * freestanding payload would drag headers that conflict with the SDK's types.h. */
#ifndef PS4RF_COMPAT_STDINT_H
#define PS4RF_COMPAT_STDINT_H

typedef __INT8_TYPE__ int8_t;
typedef __INT16_TYPE__ int16_t;
typedef __INT32_TYPE__ int32_t;
typedef __INT64_TYPE__ int64_t;
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INTPTR_TYPE__ intptr_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTMAX_TYPE__ intmax_t;
typedef __UINTMAX_TYPE__ uintmax_t;

#define INT8_MAX 127
#define INT16_MAX 32767
#define INT32_MAX 2147483647
#define INT64_MAX 9223372036854775807LL
#define INT64_MIN (-INT64_MAX - 1)
#define INT32_MIN (-INT32_MAX - 1)
#define UINT8_MAX 255u
#define UINT16_MAX 65535u
#define UINT32_MAX 4294967295u
#define UINT64_MAX 18446744073709551615ULL

#define INT8_C(c) c
#define INT16_C(c) c
#define INT32_C(c) c
#define INT64_C(c) c##LL
#define UINT8_C(c) c
#define UINT16_C(c) c
#define UINT32_C(c) c##U
#define UINT64_C(c) c##ULL

#define SIZE_MAX UINT64_MAX
#define PTRDIFF_MAX INT64_MAX

#endif /* PS4RF_COMPAT_STDINT_H */
