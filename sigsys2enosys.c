#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#define DEBUG_ENV "SIGSYS_DEBUG"
#include "config.h"
#include "debug.h"

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdint.h>
#include <limits.h>

static void handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t* ctx = (ucontext_t*)ucontext;
    int old_errno = errno;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": caught SIGSYS by syscall no. %u\n", info->si_syscall);

#ifdef __aarch64__
    ctx->uc_mcontext.regs[0] = (greg_t) -ENOSYS;
#elifdef __amd64__
    ctx->uc_mcontext.gregs[REG_RAX] = (greg_t) -ENOSYS;
#else
#error "No architecture-specific code for your plattform"
#endif

    errno = old_errno;
}

static void __attribute__((constructor)) initialize() {
    struct sigaction sig;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": registering signal handler\n");

    sig.sa_sigaction = handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_SIGINFO;

    sigaction(SIGSYS, &sig, NULL);
}
