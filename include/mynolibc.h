#pragma once

#ifdef __cplusplus
extern "C" {
#endif

//#define errno __errno_is_unsafe
#define NOLIBC_IGNORE_ERRNO

#define new mynew
#include "nolibc.h"
#undef new

#ifdef __cplusplus
}
#endif
