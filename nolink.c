
#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

int link(const char *oldpath, const char *newpath) {
    errno = ENOTSUP;
    return -1;
}

int linkat(int olddirfd, const char *oldpath,
           int newdirfd, const char *newpath, int flags) {
    errno = ENOTSUP;
    return -1;
}
