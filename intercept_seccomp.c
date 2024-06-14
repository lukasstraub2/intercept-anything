// Lots of stuff copied from nolibc
// cc -fPIC '-Wl,--defsym=__start_text=ADDR(.text)' -fvisibility=hidden -fno-omit-frame-pointer -shared -O1 -g -Wall -Wno-unused-function -Wno-comment -Wno-nonnull-compare -Wno-missing-prototypes -o intercept_seccomp.so intercept_seccomp.c

#include "common.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "config.h"
#include "debug.h"
#include "util.h"

#include <errno.h>
#include <asm/unistd.h>
#include <linux/fcntl.h>

#include <signal.h>
#include <ucontext.h>

#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

#define my_syscall0(num)                                                      \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#define my_syscall1(num, arg1)                                                \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1),                                                 \
		  "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#define my_syscall2(num, arg1, arg2)                                          \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
	register long _arg2 __asm__ ("rsi") = (long)(arg2);                   \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1), "r"(_arg2),                                     \
		  "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#define my_syscall3(num, arg1, arg2, arg3)                                    \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
	register long _arg2 __asm__ ("rsi") = (long)(arg2);                   \
	register long _arg3 __asm__ ("rdx") = (long)(arg3);                   \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3),                         \
		  "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#define my_syscall4(num, arg1, arg2, arg3, arg4)                              \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
	register long _arg2 __asm__ ("rsi") = (long)(arg2);                   \
	register long _arg3 __asm__ ("rdx") = (long)(arg3);                   \
	register long _arg4 __asm__ ("r10") = (long)(arg4);                   \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4),             \
		  "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)                        \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
	register long _arg2 __asm__ ("rsi") = (long)(arg2);                   \
	register long _arg3 __asm__ ("rdx") = (long)(arg3);                   \
	register long _arg4 __asm__ ("r10") = (long)(arg4);                   \
	register long _arg5 __asm__ ("r8")  = (long)(arg5);                   \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)                  \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
	register long _arg1 __asm__ ("rdi") = (long)(arg1);                   \
	register long _arg2 __asm__ ("rsi") = (long)(arg2);                   \
	register long _arg3 __asm__ ("rdx") = (long)(arg3);                   \
	register long _arg4 __asm__ ("r10") = (long)(arg4);                   \
	register long _arg5 __asm__ ("r8")  = (long)(arg5);                   \
	register long _arg6 __asm__ ("r9")  = (long)(arg6);                   \
										  \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), "r"(_arg5), \
		  "r"(_arg6), "0"(_num)                                       \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})


#define __sysret(arg)							\
({									\
	__typeof__(arg) __sysret_arg = (arg);				\
	(__sysret_arg < 0)                              /* error ? */	\
		? (({ errno = -__sysret_arg; }), -1) /* ret -1 with errno = -arg */ \
		: __sysret_arg;                         /* return original value */ \
})

/* Syscall ENOSYS helper: Avoids unused-parameter warnings and provides a
 * debugging hook.
 */

static __inline__ int __nolibc_enosys(const char *syscall, ...)
{
	(void)syscall;
	return -ENOSYS;
}

static __attribute__((unused))
int sys_open(const char *path, int flags, mode_t mode)
{
#ifdef __NR_openat
	return my_syscall4(__NR_openat, AT_FDCWD, path, flags, mode);
#elif defined(__NR_open)
	return my_syscall3(__NR_open, path, flags, mode);
#else
	return __nolibc_enosys(__func__, path, flags, mode);
#endif
}

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
			debug(DEBUG_LEVEL_VERBOSE, __FILE__": open(%s)\n", (const char *)args->arg1);
			ret = _open64((const char *)args->arg1, args->arg2, args->arg3);
		break;

		case __NR_openat:
			debug(DEBUG_LEVEL_VERBOSE, __FILE__": openat(%s)\n", (const char *)args->arg2);
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
	ucontext_t* ctx = (ucontext_t*)ucontext;
	int old_errno = errno;

	debug(DEBUG_LEVEL_VERBOSE, __FILE__": caught SIGSYS by syscall no. %u\n", info->si_syscall);

	unsigned long ret;
	SysArgs args = {
		.num = ctx->uc_mcontext.gregs[REG_RAX],
		.arg1 = ctx->uc_mcontext.gregs[REG_RDI],
		.arg2 = ctx->uc_mcontext.gregs[REG_RSI],
		.arg3 = ctx->uc_mcontext.gregs[REG_RDX],
		.arg4 = ctx->uc_mcontext.gregs[REG_R10],
		.arg5 = ctx->uc_mcontext.gregs[REG_R8],
		.arg6 = ctx->uc_mcontext.gregs[REG_R9]
	};
	ret = handle_syscall(&args);

#ifdef __aarch64__
	ctx->uc_mcontext.regs[0] = ret;
#elifdef __amd64__
	ctx->uc_mcontext.gregs[REG_RAX] = ret;
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
		perror("prctl(NO_NEW_PRIVS)");
		return 1;
	}
	if (prctl(PR_SET_SECCOMP, 2, &prog)) {
		perror("prctl(PR_SET_SECCOMP)");
		return 1;
	}
	return 0;
}

__attribute__((constructor))
static void init() {
	struct sigaction sig;
	static int initialized = 0;

	if (initialized) {
		return;
	}
	initialized = 1;

	debug(DEBUG_LEVEL_VERBOSE, __FILE__": registering signal handler\n");

	sig.sa_sigaction = handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_SIGINFO;

	sigaction(SIGSYS, &sig, NULL);
	install_filter();
}
