
#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#define DEBUG_ENV "NOLINK_DEBUG"
#include "debug.h"
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

int link(const char *oldpath, const char *newpath) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": link(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

    errno = ENOTSUP;
    return -1;
}

int linkat(int olddirfd, const char *oldpath,
           int newdirfd, const char *newpath, int flags) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": linkat(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

    errno = ENOTSUP;
    return -1;
}
