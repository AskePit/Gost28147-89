#ifndef PLATFORM_INCLUDE
#define PLATFORM_INCLUDE

#include <stdint.h>

#if defined (_WIN32) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(__x86_64__) || defined( __mips__ ) || defined( _mips )
        #define LITTLE_ENDIAN
#elif defined (__arm__)
        #define BIG_ENDIAN
#else
        #error "unsupported platform"
#endif

typedef uint8_t  byte;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint32_t uint;
typedef uint64_t u64;
typedef uint64_t uid;

typedef int8_t  i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#endif // PLATFORM_INCLUDE
