/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Syscall definitions for NOLIBC (those in man(2))
 * Copyright (C) 2017-2021 Willy Tarreau <w@1wt.eu>
 */

#pragma once

#include "nolibc.h"

typedef void (*sighandler_t)(int sig);

/*
 * int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
 */

static __attribute__((unused))
int sys_sigaction(int signum, const struct sigaction *act,
				  struct sigaction *oldact)
{
	return my_syscall4(__NR_rt_sigaction, signum, act, oldact,
					   sizeof(sigset_t));
}

__attribute__((weak,unused,noreturn,optimize("omit-frame-pointer"),section(".text.__restore_rt")))
void __restore_rt(void)
{
	my_syscall0(__NR_rt_sigreturn);
	__builtin_unreachable();
}

static __attribute__((unused))
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	struct sigaction act2 = *act;
	int ret;

	/*
	 * On Linux x86-64, libc's sigaction() always sets the
	 * @act->sa_restorer when the caller passes a NULL.
	 *
	 * @act->sa_restorer is an arch-specific function used
	 * as a "signal trampoline".
	 *
	 * @act->sa_handler is a signal handler provided by the
	 * user.
	 *
	 * When the handled signal is caught, the %rip jumps to
	 * @act->sa_handler with user stack already set by the
	 * kernel as below:
	 *
	 *         |--------------------|
	 * %rsp -> |  act->sa_restorer  | (return address)
	 *         |--------------------|
	 *         | struct rt_sigframe | (process context info)
	 *         |                    |
	 *         |                    |
	 *          ....................
	 *
	 * Once this signal handler executes the "ret" instruction,
	 * the %rip jumps to @act->sa_restorer. The sa_restorer
	 * function has to invoke the __rt_sigreturn syscall with
	 * %rsp pointing to the `struct rt_sigframe` that the kernel
	 * constructed previously to resume the process.
	 *
	 * `struct rt_sigframe` contains the registers' value before
	 * the signal is caught.
	 *
	 */
	if (!act2.sa_restorer) {
		act2.sa_flags |= SA_RESTORER;
		act2.sa_restorer = __restore_rt;
	}

	ret = sys_sigaction(signum, &act2, oldact);
	if (ret < 0) {
		return ret;
	}
	return ret;
}
