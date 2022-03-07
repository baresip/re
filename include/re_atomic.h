#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_ATOMIC
#include <stdatomic.h>
#elif __has_extension(c_atomic)
#define	__CLANG_ATOMICS
#elif __GNUC_PREREQ__(4, 7)
#define	__GNUC_ATOMICS
#elif defined(__GNUC__)
#define	__SYNC_ATOMICS
#else
#error "Your compiler does not support atomics"
#endif

#ifdef __cplusplus
}
#endif
