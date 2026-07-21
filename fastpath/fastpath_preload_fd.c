#undef _FORTIFY_SOURCE

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "fastpath_preload.h"

#include <errno.h>
#include <syscall.h>
#include <unistd.h>

#undef close
int close(int fd) {
    int ret;

    maybe_init();

    ret = entry(__NR_close, fd, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef close_range
int close_range(unsigned int fd, unsigned int max_fd, int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_close_range, fd, max_fd, flags, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}