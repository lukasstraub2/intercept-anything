#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "config.h"

#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdint.h>
#include <limits.h>

static void debug(int level, const char *format, ...) __attribute__((format (printf, 2, 3)));

#define DEBUG_LEVEL_ALWAYS                0
#define DEBUG_LEVEL_NORMAL                1
#define DEBUG_LEVEL_VERBOSE               2

static void debug(int level, const char *format, ...) {
    va_list ap;
    const char *dlevel_s;
    int dlevel;

    dlevel_s = getenv("SIGSYS_DEBUG");
    if (!dlevel_s)
        return;

    dlevel = atoi(dlevel_s);

    if (dlevel < level)
        return;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

static void handler(int sig, siginfo_t *info, void *ucontext) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": caught SIGSYS by syscall no. %u\n", info->si_syscall);

    info->si_errno = ENOSYS;
}

static void __attribute__((constructor)) initialize() {
    struct sigaction sig;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": registering signal handler\n");

    sig.sa_sigaction = handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_SIGINFO;

    sigaction(SIGSYS, &sig, NULL);
}
