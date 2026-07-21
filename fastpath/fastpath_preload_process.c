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
#include <signal.h>

#undef kill
int kill(pid_t pid, int sig) {
    int ret;

    maybe_init();

    ret = entry(__NR_kill, pid, sig, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}