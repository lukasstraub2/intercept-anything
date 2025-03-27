#pragma once

typedef struct SysArgs SysArgs;
struct SysArgs {
    unsigned long num;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
    unsigned long arg6;
};

#if defined(__x86_64__)
#include "myseccomp-x86_64.h"
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || \
    defined(__i686__)
#include "myseccomp-i386.h"
#elif defined(__aarch64__)
#include "myseccomp-aarch64.h"
#else
#error Unsupported Architecture
#endif
