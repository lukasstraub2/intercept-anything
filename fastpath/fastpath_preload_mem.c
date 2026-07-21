#undef _FORTIFY_SOURCE

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "fastpath_preload.h"

#include <errno.h>
#include <unistd.h>
#include <syscall.h>

#undef msync
int msync(void* addr, size_t len, int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_msync, (unsigned long)addr, len, flags, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}