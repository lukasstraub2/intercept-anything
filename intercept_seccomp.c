
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

static int handle_open(const char *path, int flags, mode_t mode) {
	trace("open(%s)\n", path);
	return __sysret(sys_open(path, flags, mode));
}

static __attribute__((unused))
int sys_openat(int dirfd, const char *path, int flags, mode_t mode) {
#ifdef __NR_openat
	return my_syscall4(__NR_openat, dirfd, path, flags, mode);
#else
	return __nolibc_enosys(__func__, path, flags, mode);
#endif
}

static int handle_openat(int dirfd, const char *path, int flags, mode_t mode) {
	trace("openat(%s)\n", path);
	return __sysret(sys_openat(dirfd, path, flags, mode));
}

static int sys_stat(const char *path, void *statbuf) {
	return my_syscall2(__NR_stat, path, statbuf);
}

static int handle_stat(const char *path, void *statbuf) {
	trace("stat(%s)\n", path);
	return __sysret(sys_stat(path, statbuf));
}

static int sys_fstat(int fd, void *statbuf) {
	return my_syscall2(__NR_fstat, fd, statbuf);
}

static int handle_fstat(int fd, void *statbuf) {
	trace("fstat(%u)\n", fd);
	return __sysret(sys_fstat(fd, statbuf));
}

static int sys_lstat(const char *path, void *statbuf) {
	return my_syscall2(__NR_lstat, path, statbuf);
}

static int handle_lstat(const char *path, void *statbuf) {
	trace("lstat(%s)\n", path);
	return __sysret(sys_lstat(path, statbuf));
}

static int sys_newfstatat(int dirfd, const char *path, void *statbuf,
						  int flags) {
	return my_syscall4(__NR_newfstatat, dirfd, path, statbuf, flags);
}

static int handle_newfstatat(int dirfd, const char *path, void *statbuf,
							 int flags) {
	trace("newfstatat(%s)\n", path);
	return __sysret(sys_newfstatat(dirfd, path, statbuf, flags));
}

static int handle_statx(int dirfd, const char *path, int flags,
						unsigned int mask, void *statbuf) {
	trace("statx(%s)\n", path);
	return __sysret(sys_statx(dirfd, path, flags, mask, statbuf));
}

static signed
long sys_readlink(const char *path, char *buf, unsigned long bufsiz) {
	return my_syscall3(__NR_readlink, path, buf, bufsiz);
}

static signed
long handle_readlink(const char *path, char *buf, unsigned long bufsiz) {
	trace("readlink(%s)\n", path);
	return __sysret(sys_readlink(path, buf, bufsiz));
}

static signed
long sys_readlinkat(int dirfd, const char *path, char *buf,
					unsigned long bufsiz) {
	return my_syscall4(__NR_readlinkat, dirfd, path, buf, bufsiz);
}

static signed
long handle_readlinkat(int dirfd, const char *path, char *buf,
					   unsigned long bufsiz) {
	trace("readlinkat(%s)\n", path);
	return __sysret(sys_readlinkat(dirfd, path, buf, bufsiz));
}

static int sys_faccessat(int dirfd, const char *path, int mode) {
	return my_syscall3(__NR_faccessat, dirfd, path, mode);
}

static int handle_faccessat(int dirfd, const char *path, int mode) {
	trace("faccessat(%s)\n", path);
	return __sysret(sys_faccessat(dirfd, path, mode));
}

static int sys_access(const char *path, int mode) {
	return my_syscall2(__NR_faccessat, path, mode);
}

static int handle_access(const char *path, int mode) {
	trace("access(%s)\n", path);
	return __sysret(sys_access(path, mode));
}

static int handle_execve(const char *path, char *const argv[], char *const envp[]) {
	trace("execve(%s)\n", path);
	return __sysret(sys_execve(path, argv, envp));
}

static int sys_execveat(int dirfd, const char *path, char *const argv[],
						char *const envp[], int flags) {
	return my_syscall5(__NR_execveat, dirfd, path, argv, envp, flags);
}

static int handle_execveat(int dirfd, const char *path, char *const argv[],
						   char *const envp[], int flags) {
	trace("execveat(%s)\n", path);
	return __sysret(sys_execveat(dirfd, path, argv, envp, flags));
}

static int sys_rt_sigprocmask(int how, const sigset_t *set,
							  sigset_t *oldset, size_t sigsetsize) {
	return my_syscall4(__NR_rt_sigprocmask, how, set, oldset, sigsetsize);
}

static int handle_rt_sigprocmask(int how, const sigset_t *set,
								 sigset_t *oldset, size_t sigsetsize) {
	trace("rt_sigprocmask()\n");
	return __sysret(sys_rt_sigprocmask(how, set, oldset, sigsetsize));
}

static long sys_rt_sigaction(int signum, const struct sigaction *act,
							 struct sigaction *oldact, size_t sigsetsize) {
	return my_syscall4(__NR_rt_sigaction, signum, act, oldact, sigsetsize);
}

static long handle_rt_sigaction(int signum, const struct sigaction *act,
								struct sigaction *oldact, size_t sigsetsize) {
	trace("rt_sigaction(%d)\n", signum);

	// TODO: Move this to filter chain
	if (signum == SIGSYS) {
		return 0;
	}

	return __sysret(sys_rt_sigaction(signum, act, oldact, sigsetsize));
}

static unsigned long handle_syscall(SysArgs *args) {
	int ret;

	switch (args->num) {
#ifdef __NR_open
		case __NR_open:
			ret = handle_open((const char *)args->arg1, args->arg2, args->arg3);
		break;
#endif

		case __NR_openat:
			ret = handle_openat(args->arg1, (const char *)args->arg2,
								args->arg3, args->arg4);
		break;

		case __NR_stat:
			ret = handle_stat((const char *)args->arg1, (void *)args->arg2);
		break;

		case __NR_fstat:
			ret = handle_fstat(args->arg1, (void *)args->arg2);
		break;

		case __NR_lstat:
			ret = handle_lstat((const char *)args->arg1, (void *)args->arg2);
		break;

		case __NR_newfstatat:
			ret = handle_newfstatat(args->arg1, (const char *)args->arg2,
									(void *)args->arg3, args->arg4);
		break;

		case __NR_statx:
			ret = handle_statx(args->arg1, (const char *)args->arg2,
							   args->arg3, args->arg4, (void *)args->arg5);
		break;

		case __NR_readlink:
			ret = handle_readlink((const char *)args->arg1, (char *)args->arg2,
								  args->arg3);
		break;

		case __NR_readlinkat:
			ret = handle_readlinkat(args->arg1, (const char *)args->arg2,
									(char *)args->arg3, args->arg4);
		break;

		case __NR_faccessat:
			ret = handle_faccessat(args->arg1, (const char *)args->arg2, args->arg3);
		break;

		case __NR_access:
			ret = handle_access((const char *)args->arg1, args->arg2);
		break;

		case __NR_execve:
			ret = handle_execve((const char *)args->arg1,
								(char *const *)args->arg2,
								(char *const *)args->arg3);
		break;

		case __NR_execveat:
			ret = handle_execveat(args->arg1, (const char *)args->arg2,
								  (char *const *)args->arg3,
								  (char *const *)args->arg4,
								  args->arg5);
		break;

		case __NR_rt_sigprocmask:
			ret = handle_rt_sigprocmask(args->arg1, (const sigset_t *)args->arg2,
										(sigset_t *)args->arg3, args->arg4);
		break;

		case __NR_rt_sigaction:
			ret = handle_rt_sigaction(args->arg1,
									  (const struct sigaction *)args->arg2,
									  (struct sigaction *)args->arg3, args->arg4);
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
	(void) sig;

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
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 15, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 15, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 14, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 13, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 12, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 11, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_newfstatat, 10, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_statx, 9, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 8, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlinkat, 7, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_access, 6, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_faccessat, 5, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 4, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 3, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigprocmask, 2, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 1, 0),
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
