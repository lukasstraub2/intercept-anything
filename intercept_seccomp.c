// Lots of stuff copied from nolibc

#include "nolibc.h"
#include "mysignal.h"

#include <asm/siginfo.h>

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

#include <asm/sigcontext.h>
#include <asm/ucontext.h>

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

typedef struct SysArgs SysArgs;
struct SysArgs {
	unsigned long num;
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
	unsigned long arg6;
};

unsigned long handle_syscall(SysArgs *args) {
	int ret;

	switch (args->num) {
		case __NR_open:
			trace(": open(%s)\n", (const char *)args->arg1);
			ret = _open64((const char *)args->arg1, args->arg2, args->arg3);
		break;

		case __NR_openat:
			trace(": openat(%s)\n", (const char *)args->arg2);
			ret = _openat64(args->arg1, (const char *)args->arg2, args->arg3,
							args->arg4);
		break;

		default:
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
	struct ucontext* ctx = (struct ucontext*)ucontext;
	int old_errno = errno;

	trace(": caught SIGSYS by syscall no. %u\n", info->si_syscall);

	unsigned long ret;
	SysArgs args = {
		.num = ctx->uc_mcontext.rax,
		.arg1 = ctx->uc_mcontext.rdi,
		.arg2 = ctx->uc_mcontext.rsi,
		.arg3 = ctx->uc_mcontext.rdx,
		.arg4 = ctx->uc_mcontext.r10,
		.arg5 = ctx->uc_mcontext.r8,
		.arg6 = ctx->uc_mcontext.r9
	};
	ret = handle_syscall(&args);

#ifdef __aarch64__
	ctx->uc_mcontext.regs[0] = ret;
#elifdef __amd64__
	ctx->uc_mcontext.rax = ret;
#else
#error "No architecture-specific code for your plattform"
#endif

	errno = old_errno;
}

extern char __start_text;
extern char __etext;

static int install_filter() {
	const int arch = AUDIT_ARCH_X86_64;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 9),
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 1, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 6),
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

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		exit_error("prctl(NO_NEW_PRIVS)");
		return 1;
	}

	if (prctl(PR_SET_SECCOMP, 2, (unsigned long) &prog, 0, 0)) {
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
