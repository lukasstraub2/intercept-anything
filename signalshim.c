
#include "common.h"

#include "signalshim.h"
#define DEBUG_ENV "SIGNALSHIM_DEBUG"
#include "config.h"
#include "debug.h"
#include "intercept.h"

#include <errno.h>
#include <signal.h>
#include <ucontext.h>

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

const CallHandler *signalshim_init(const CallHandler *next) {
	struct sigaction sig;
	static int initialized = 0;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": registering signal handler\n");

    sig.sa_sigaction = handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_SIGINFO;

    sigaction(SIGSYS, &sig, NULL);

	return next;
}
