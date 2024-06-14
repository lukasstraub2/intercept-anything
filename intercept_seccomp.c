// Lots of stuff copied from nolibc

#include "nolibc.h"
#include "mysignal.h"
#include "myseccomp.h"

#include <asm/siginfo.h>

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

int _open64(const char *path, int flags, mode_t mode) {
	return __sysret(sys_open(path, flags, mode));
}

static __attribute__((unused))
int sys_openat(int dirfd, const char *path, int flags, mode_t mode)
{
#ifdef __NR_openat
	return my_syscall4(__NR_openat, dirfd, path, flags, mode);
#else
	return __nolibc_enosys(__func__, path, flags, mode);
#endif
}

int _openat64(int dirfd, const char *path, int flags, mode_t mode) {
	return __sysret(sys_openat(dirfd, path, flags, mode));
}

unsigned long handle_syscall(SysArgs *args) {
	int ret;

	switch (args->num) {
#ifdef __NR_open
		case __NR_open:
			trace("open(%s)\n", (const char *)args->arg1);
			ret = _open64((const char *)args->arg1, args->arg2, args->arg3);
		break;
#endif

		case __NR_openat:
			trace("openat(%s)\n", (const char *)args->arg2);
			ret = _openat64(args->arg1, (const char *)args->arg2, args->arg3,
							args->arg4);
		break;

		default:
			debug("Unhandled syscall no. %lu\n", args->num);
			errno = ENOSYS;
			ret = -1;
		break;
	}

	if (ret < 0) {
		return -errno;
	}

	return ret;
}

static void handler(int sig, siginfo_t *info, void *ucontext) {
	if (info->si_errno) {
		fprintf(stderr, "Invalid arch, terminating\n");
		exit(1);
	}

	unsigned long ret;
	SysArgs args;
	fill_sysargs(&args, ucontext);
	ret = handle_syscall(&args);

	set_return(ucontext, ret);
}

extern char __start_text;
extern char __etext;

static int install_filter() {
	int ret;

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP | (1 & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
#ifdef __NR_open
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 2, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 1, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 1, 0),
#endif
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, instruction_pointer) + 4)),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ((unsigned long)&__start_text) >> 32, 0, 3),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, instruction_pointer))),
		BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (unsigned long)&__start_text, 0, 1),
		BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, (unsigned long)&__etext, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP),
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	/* First try without dropping privileges */
	ret = prctl(PR_SET_SECCOMP, 2, (unsigned long) &prog, 0, 0);
	if (ret == 0) {
		return 0;
	}

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (ret < 0) {
		exit_error("prctl(NO_NEW_PRIVS)");
		return 1;
	}

	ret = prctl(PR_SET_SECCOMP, 2, (unsigned long) &prog, 0, 0);
	if (ret < 0) {
		exit_error("prctl(PR_SET_SECCOMP)");
		return 1;
	}

	return 0;
}

void intercept_init() {
	struct sigaction sig = {0};
	static int initialized = 0;

	if (initialized) {
		return;
	}
	initialized = 1;

	trace("registering signal handler\n");

	sig.sa_handler = handler;
	//sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_SIGINFO;

	sigaction(SIGSYS, &sig, NULL);
	install_filter();
}
