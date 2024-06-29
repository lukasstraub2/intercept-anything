
#include "nolibc.h"
#include "mysignal.h"
#include "myseccomp.h"
#include "mysys.h"
#include "intercept.h"
#include "loader.h"
#include "mytypes.h"
#include "config.h"
#include "tls.h"
#include "util.h"

#include <asm/siginfo.h>

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static const CallHandler bottom;
static const CallHandler *_next = NULL;

static int install_filter();
static void handler(int sig, siginfo_t *info, void *ucontext);
static unsigned long handle_syscall(SysArgs *args, void *ucontext);

static void unblock_sigsys() {
	unsigned long unblock = (1u << (SIGSYS -1));
	sys_rt_sigprocmask(SIG_UNBLOCK, &unblock, NULL, sizeof(unblock));
}

void intercept_init(int recursing) {
	struct sigaction sig = {0};
	static int initialized = 0;

	if (initialized) {
		return;
	}
	initialized = 1;

	sig.sa_handler = handler;
	//sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_NODEFER | SA_SIGINFO;

	sigaction(SIGSYS, &sig, NULL);
	unblock_sigsys();
	trace("registered signal handler\n");

	if (!recursing) {
		install_filter();
	}

	_next = main_init(&bottom);
}

static void handler(int sig, siginfo_t *info, void *ucontext) {
	(void) sig;

	if (info->si_errno) {
		fprintf(stderr, "Invalid arch, terminating\n");
		exit(1);
	}

	ssize_t ret;
	SysArgs args;
	fill_sysargs(&args, ucontext);
	ret = handle_syscall(&args, ucontext);

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
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 40, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 39, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chdir, 38, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fchdir, 37, 0),
#ifdef __NR_open
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 36, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 36, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 35, 0),
#ifdef __NR_stat
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 34, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 34, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 33, 0),
#ifdef __NR_lstat
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 32, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 32, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_newfstatat, 31, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_statx, 30, 0),
#ifdef __NR_readlink
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 29, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 29, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlinkat, 28, 0),
#ifdef __NR_access
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_access, 27, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 27, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_faccessat, 26, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 25, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 24, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigprocmask, 23, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 22, 0),
#ifdef __NR_link
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_link, 21, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 21, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_linkat, 20, 0),
#ifdef __NR_symlink
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlink, 19, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 19, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlinkat, 18, 0),
#ifdef __NR_unlink
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlink, 17, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 17, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlinkat, 16, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_setxattr, 15, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lsetxattr, 14, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fsetxattr, 13, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_getxattr, 12, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lgetxattr, 11, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fgetxattr, 10, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_listxattr, 9, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_llistxattr, 8, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_flistxattr, 7, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_removexattr, 6, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lremovexattr, 5, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fremovexattr, 4, 0),
#ifdef __NR_rename
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rename, 3, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 3, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_renameat, 2, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_renameat2, 1, 0),
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

static int64_t array_len(char *const array[]) {
	int64_t len;

	for (len = 0; array[len]; len++) {
		if (len == INT_MAX) {
			return -1;
		}
	}

	return len;
}

static void array_copy(char *dest[], char *const source[], int64_t len) {
	memcpy(dest, source, len * sizeof(char *));
}

static int cmdline_argc(char *buf, ssize_t size) {
	int argc = 0;
	int whitespace = 1;

	for (int i = 2; i < size; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			return argc;
		} else if (buf[i] != ' ' && buf[i] != '\t') {
			if (whitespace) {
				argc++;
				whitespace = 0;
			}
		} else {
			whitespace = 1;
		}
	}

	return argc;
}

static void cmdline_extract(char *buf, ssize_t size, char **dest) {
	int argc = 0;
	int whitespace = 1;

	for (int i = 2; i < size; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			buf[i] = '\0';
			return;
		} else if (buf[i] != ' ' && buf[i] != '\t') {
			if (whitespace) {
				dest[argc] = buf + i;
				argc++;
				whitespace = 0;
			}
		} else {
			buf[i] = '\0';
			whitespace = 1;
		}
	}

	buf[size -1] = '\0';
	return;
}

static void debug_exec(const char *pathname, char *const argv[],
					   char *const envp[]) {
	int64_t i;

	trace(": recurse execve(%s, [ ", pathname?pathname:"NULL");

	for (i = 0; argv[i]; i++) {
		trace( "%s, ", argv[i]);
	}

	trace( "], envp)\n");
}

static ssize_t read_full(int fd, char *buf, size_t count)
{
	ssize_t ret = 0;
	ssize_t total = 0;

	while (count) {
		ret = read(fd, buf, count);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if (ret == 0) {
			break;
		}

		count -= ret;
		buf += ret;
		total += ret;
	}

	return total;
}

static void context_fill(Context *ctx) {
	pid_t tid = gettid();
	trace_plus("gettid(): %u\n", tid);
	ctx->tls = _tls_get(tid);
}

static void thread_exit() {
	tls_free();
}

__attribute__((unused))
static int handle_open(const char *path, int flags, mode_t mode) {
	trace("open(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.at = 0,
		.path = path,
		.flags = flags,
		.mode = mode,
		.ret = &ret
	};

	_next->open(&ctx, _next->open_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_openat(int dirfd, const char *path, int flags, mode_t mode) {
	trace("openat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.at = 1,
		.dirfd = dirfd,
		.path = path,
		.flags = flags,
		.mode = mode,
		.ret = &ret
	};

	_next->open(&ctx, _next->open_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static int handle_stat(const char *path, void *statbuf) {
	trace("stat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_PLAIN,
		.path = path,
		.statbuf = statbuf,
		.ret = &ret
	};

	_next->stat(&ctx, _next->stat_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_fstat(int fd, void *statbuf) {
	trace("fstat()\n");

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_F,
		.dirfd = fd,
		.statbuf = statbuf,
		.ret = &ret
	};

	_next->stat(&ctx, _next->stat_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static int handle_lstat(const char *path, void *statbuf) {
	trace("lstat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_L,
		.path = path,
		.statbuf = statbuf,
		.ret = &ret
	};

	_next->stat(&ctx, _next->stat_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_newfstatat(int dirfd, const char *path, void *statbuf,
							 int flags) {
	trace("newfstatat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_AT,
		.dirfd = dirfd,
		.path = path,
		.statbuf = statbuf,
		.flags = flags,
		.ret = &ret
	};

	_next->stat(&ctx, _next->stat_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_statx(int dirfd, const char *path, int flags,
						unsigned int mask, void *statbuf) {
	trace("statx(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_X,
		.dirfd = dirfd,
		.path = path,
		.flags = flags,
		.mask = mask,
		.statbuf = statbuf,
		.ret = &ret
	};

	_next->stat(&ctx, _next->stat_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static ssize_t handle_readlink(const char *path, char *buf, size_t bufsiz) {
	trace("readlink(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallReadlink call = {
		.at = 0,
		.path = path,
		.buf = buf,
		.bufsiz = bufsiz,
		.ret = &ret
	};

	_next->readlink(&ctx, _next->readlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz) {
	trace("readlinkat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallReadlink call = {
		.at = 1,
		.dirfd = dirfd,
		.path = path,
		.buf = buf,
		.bufsiz = bufsiz,
		.ret = &ret
	};

	_next->readlink(&ctx, _next->readlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static int handle_access(const char *path, int mode) {
	trace("access(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallAccess call = {
		.at = 0,
		.path = path,
		.mode = mode,
		.ret = &ret
	};

	_next->access(&ctx, _next->access_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_faccessat(int dirfd, const char *path, int mode) {
	trace("accessat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallAccess call = {
		.at = 1,
		.dirfd = dirfd,
		.path = path,
		.mode = mode,
		.ret = &ret
	};

	_next->access(&ctx, _next->access_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_execve(const char *path, char *const argv[], char *const envp[]) {
	trace("execve(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallExec call = {
		.at = 0,
		.path = path,
		.argv = argv,
		.envp = envp,
		.ret = &ret
	};

	_next->exec(&ctx, _next->exec_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_execveat(int dirfd, const char *path, char *const argv[],
						   char *const envp[], int flags) {
	trace("exeveat(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallExec call = {
		.at = 1,
		.dirfd = dirfd,
		.path = path,
		.argv = argv,
		.envp = envp,
		.flags = flags,
		.ret = &ret
	};

	_next->exec(&ctx, _next->exec_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_rt_sigprocmask(int how, const sigset_t *set,
								 sigset_t *oldset, size_t sigsetsize,
								 void *ucontext) {
	struct ucontext* ctx = (struct ucontext*)ucontext;
	char *cur_set = (char *)&ctx->uc_sigmask;
	int ret;

	trace("rt_sigprocmask()\n");

	if (!set) {
		return __sysret(sys_rt_sigprocmask(how, set, oldset, sigsetsize));
	}

	unsigned char copy[sigsetsize];
	memcpy(copy, set, sigsetsize);
	copy[3] &= ~(0x40); // Clear SIGSYS

	ret = __sysret(sys_rt_sigprocmask(how, (sigset_t *)copy, oldset, sigsetsize));
	if (ret < 0) {
		return -1;
	}

	// Any changes to sigprocmask would be reset on sigreturn
	switch (how) {
		case SIG_BLOCK:
			for (unsigned int i = 0; i < sigsetsize; i++) {
				cur_set[i] |= copy[i];
			}
			return 0;
		break;

		case SIG_UNBLOCK:
			for (unsigned int i = 0; i < sigsetsize; i++) {
				cur_set[i] &= ~copy[i];
			}
			return 0;
		break;

		case SIG_SETMASK:
			memcpy(cur_set, copy, sigsetsize);
			return 0;
		break;

		default:
			errno = EINVAL;
			return -1;
		break;
	}
}

static long handle_rt_sigaction(int signum, const struct sigaction *act,
								struct sigaction *oldact, size_t sigsetsize) {
	trace("rt_sigaction(%d)\n", signum);

	// TODO: Move this to filter chain
	if (signum == SIGSYS) {
		return 0;
	}

	if (!act) {
		return __sysret(sys_rt_sigaction(signum, act, oldact, sigsetsize));
	}

	size_t size = sizeof(struct sigaction) + sigsetsize - sizeof(sigset_t);
	unsigned char _copy[size];
	memcpy(_copy, act, size);
	struct sigaction *copy = (struct sigaction *)_copy;
	char *sa_mask = (char *)&copy->sa_mask;
	sa_mask[3] &= ~(0x40); // Clear SIGSYS

	return __sysret(sys_rt_sigaction(signum, copy, oldact, sigsetsize));
}

__attribute__((unused))
static int handle_link(const char *oldpath, const char *newpath) {
	trace("link(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 0,
		.oldpath = oldpath,
		.newpath = newpath,
		.ret = &ret
	};

	_next->link(&ctx, _next->link_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_linkat(int olddirfd, const char *oldpath, int newdirfd,
						 const char *newpath, int flags) {
	trace("linkat(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 1,
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.flags = flags,
		.ret = &ret
	};

	_next->link(&ctx, _next->link_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static int handle_symlink(const char *oldpath, const char *newpath) {
	trace("symlink(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 0,
		.oldpath = oldpath,
		.newpath = newpath,
		.ret = &ret
	};

	_next->symlink(&ctx, _next->symlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_symlinkat(const char *oldpath, int newdirfd,
							const char *newpath) {
	trace("symlinkat(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 1,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.ret = &ret
	};

	_next->symlink(&ctx, _next->symlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static int handle_unlink(const char *pathname) {
	trace("unlink(%s)\n", pathname);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallUnlink call = {
		.at = 0,
		.path = pathname,
		.ret = &ret
	};

	_next->unlink(&ctx, _next->unlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_unlinkat(int dirfd, const char *pathname, int flags) {
	trace("unlinkat(%s)\n", pathname);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallUnlink call = {
		.at = 1,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.ret = &ret
	};

	_next->unlink(&ctx, _next->unlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	trace("setxattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_SET,
		.type2 = XATTRTYPE_PLAIN,
		.path = path,
		.name = name,
		.value = (void *)value,
		.size = size,
		.flags = flags,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	trace("lsetxattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_SET,
		.type2 = XATTRTYPE_L,
		.path = path,
		.name = name,
		.value = (void *)value,
		.size = size,
		.flags = flags,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
	trace("fsetxattr(%d)\n", fd);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_SET,
		.type2 = XATTRTYPE_F,
		.fd = fd,
		.name = name,
		.value = (void *)value,
		.size = size,
		.flags = flags,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_getxattr(const char *path, const char *name, void *value, size_t size) {
	trace("getxattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_GET,
		.type2 = XATTRTYPE_PLAIN,
		.path = path,
		.name = name,
		.value = value,
		.size = size,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_lgetxattr(const char *path, const char *name, void *value, size_t size) {
	trace("lgetxattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_GET,
		.type2 = XATTRTYPE_L,
		.path = path,
		.name = name,
		.value = value,
		.size = size,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_fgetxattr(int fd, const char *name, void *value, size_t size) {
	trace("fgetxattr(%d)\n", fd);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_GET,
		.type2 = XATTRTYPE_F,
		.fd = fd,
		.name = name,
		.value = value,
		.size = size,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_listxattr(const char *path, char *list, size_t size) {
	trace("listxattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_LIST,
		.type2 = XATTRTYPE_PLAIN,
		.path = path,
		.list = list,
		.size = size,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_llistxattr(const char *path, char *list, size_t size) {
	trace("llistxattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_LIST,
		.type2 = XATTRTYPE_L,
		.path = path,
		.list = list,
		.size = size,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static ssize_t handle_flistxattr(int fd, char *list, size_t size) {
	trace("flistxattr(%d)\n", fd);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_LIST,
		.type2 = XATTRTYPE_F,
		.fd = fd,
		.list = list,
		.size = size,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_removexattr(const char *path, const char *name) {
	trace("removexattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_REMOVE,
		.type2 = XATTRTYPE_PLAIN,
		.path = path,
		.name = name,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_lremovexattr(const char *path, const char *name) {
	trace("lremovexattr(%s)\n", path);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_REMOVE,
		.type2 = XATTRTYPE_L,
		.path = path,
		.name = name,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_fremovexattr(int fd, const char *name) {
	trace("fremovexattr(%d)\n", fd);

	Context ctx;
	context_fill(&ctx);
	RetSSize ret = { ._errno = errno };
	CallXattr call = {
		.type = XATTRTYPE_REMOVE,
		.type2 = XATTRTYPE_F,
		.fd = fd,
		.name = name,
		.ret = &ret
	};

	_next->xattr(&ctx, _next->xattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((unused))
static int handle_rename(const char *oldpath, const char *newpath) {
	trace("rename(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallRename call = {
		.type = RENAMETYPE_PLAIN,
		.oldpath = oldpath,
		.newpath = newpath,
		.ret = &ret
	};

	_next->rename(&ctx, _next->rename_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_renameat(int olddirfd, const char *oldpath,
						   int newdirfd, const char *newpath) {
	trace("renameat(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallRename call = {
		.type = RENAMETYPE_AT,
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.ret = &ret
	};

	_next->rename(&ctx, _next->rename_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_renameat2(int olddirfd, const char *oldpath,
							int newdirfd, const char *newpath, unsigned int flags) {
	trace("renameat2(%s, %s)\n", oldpath, newpath);

	Context ctx;
	context_fill(&ctx);
	RetInt ret = { ._errno = errno };
	CallRename call = {
		.type = RENAMETYPE_AT2,
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.flags = flags,
		.ret = &ret
	};

	_next->rename(&ctx, _next->rename_next, &call);
	errno = ret._errno;
	return ret.ret;
}

static int handle_chdir(const char *path) {
	trace("chdir(%s)\n", path);
	return __sysret(sys_chdir(path));
}

static int handle_fchdir(int fd) {
	trace("fchdir(%d)\n", fd);
	return __sysret(sys_fchdir(fd));
}

static int handle_exit(int status) {
	trace("exit(%u)\n", status);

	thread_exit();

	sys_exit(status);
	return 0;
}

static int handle_exit_group(int status) {
	trace("exit_group(%u)\n", status);

	thread_exit();

	sys_exit_group(status);
	return 0;
}

static unsigned long handle_syscall(SysArgs *args, void *ucontext) {
	ssize_t ret;

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

#ifdef __NR_stat
		case __NR_stat:
			ret = handle_stat((const char *)args->arg1, (void *)args->arg2);
		break;
#endif

		case __NR_fstat:
			ret = handle_fstat(args->arg1, (void *)args->arg2);
		break;

#ifdef __NR_lstat
		case __NR_lstat:
			ret = handle_lstat((const char *)args->arg1, (void *)args->arg2);
		break;
#endif

		case __NR_newfstatat:
			ret = handle_newfstatat(args->arg1, (const char *)args->arg2,
									(void *)args->arg3, args->arg4);
		break;

		case __NR_statx:
			ret = handle_statx(args->arg1, (const char *)args->arg2,
							   args->arg3, args->arg4, (void *)args->arg5);
		break;

#ifdef __NR_readlink
		case __NR_readlink:
			ret = handle_readlink((const char *)args->arg1, (char *)args->arg2,
								  args->arg3);
		break;
#endif

		case __NR_readlinkat:
			ret = handle_readlinkat(args->arg1, (const char *)args->arg2,
									(char *)args->arg3, args->arg4);
		break;

#ifdef __NR_access
		case __NR_access:
			ret = handle_access((const char *)args->arg1, args->arg2);
		break;
#endif

		case __NR_faccessat:
			ret = handle_faccessat(args->arg1, (const char *)args->arg2, args->arg3);
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
										(sigset_t *)args->arg3, args->arg4,
										ucontext);
		break;

		case __NR_rt_sigaction:
			ret = handle_rt_sigaction(args->arg1,
									  (const struct sigaction *)args->arg2,
									  (struct sigaction *)args->arg3, args->arg4);
		break;

#ifdef __NR_link
		case __NR_link:
			ret = handle_link((const char *)args->arg1, (const char *)args->arg2);
		break;
#endif

		case __NR_linkat:
			ret = handle_linkat(args->arg1, (const char *)args->arg2, args->arg3,
								(const char *)args->arg4, args->arg5);
		break;

#ifdef __NR_symlink
		case __NR_symlink:
			ret = handle_symlink((const char *)args->arg1,
								 (const char *)args->arg2);
		break;
#endif

		case __NR_symlinkat:
			ret = handle_symlinkat((const char *)args->arg1, args->arg2,
								   (const char *)args->arg3);
		break;

#ifdef __NR_unlink
		case __NR_unlink:
			ret = handle_unlink((const char *)args->arg1);
		break;
#endif

		case __NR_unlinkat:
			ret = handle_unlinkat(args->arg1, (const char *)args->arg2, args->arg3);
		break;

		case __NR_setxattr:
			ret = handle_setxattr((const char *)args->arg1,
								  (const char *)args->arg2,
								  (const void *)args->arg3,
								  args->arg4, args->arg5);
		break;

		case __NR_lsetxattr:
			ret = handle_lsetxattr((const char *)args->arg1,
								   (const char *)args->arg2,
								   (const void *)args->arg3,
								   args->arg4, args->arg5);
		break;

		case __NR_fsetxattr:
			ret = handle_fsetxattr(args->arg1, (const char *)args->arg2,
								   (const void *)args->arg3, args->arg4,
								   args->arg5);
		break;

		case __NR_getxattr:
			ret = handle_getxattr((const char *)args->arg1,
								  (const char *)args->arg2,
								  (void *)args->arg3, args->arg4);
		break;

		case __NR_lgetxattr:
			ret = handle_lgetxattr((const char *)args->arg1,
								   (const char *)args->arg2,
								   (void *)args->arg3, args->arg4);
		break;

		case __NR_fgetxattr:
			ret = handle_fgetxattr(args->arg1, (const char *)args->arg2,
								   (void *)args->arg3, args->arg4);
		break;

		case __NR_listxattr:
			ret = handle_listxattr((const char *)args->arg1,
								   (char *)args->arg2, args->arg3);
		break;

		case __NR_llistxattr:
			ret = handle_llistxattr((const char *)args->arg1,
									(char *)args->arg2, args->arg3);
		break;

		case __NR_flistxattr:
			ret = handle_flistxattr(args->arg1, (char *)args->arg2, args->arg3);
		break;

		case __NR_removexattr:
			ret = handle_removexattr((const char*)args->arg1,
									 (const char*)args->arg2);
		break;

		case __NR_lremovexattr:
			ret = handle_lremovexattr((const char*)args->arg1,
									  (const char*)args->arg2);
		break;

		case __NR_fremovexattr:
			ret = handle_fremovexattr(args->arg1, (const char*)args->arg2);
		break;

#ifdef __NR_rename
		case __NR_rename:
			ret = handle_rename((const char *)args->arg1, (const char *)args->arg2);
		break;
#endif

		case __NR_renameat:
			ret = handle_renameat(args->arg1, (const char *)args->arg2,
								  args->arg3, (const char *)args->arg4);
		break;

		case __NR_renameat2:
			ret = handle_renameat2(args->arg1, (const char *)args->arg2,
								   args->arg3, (const char *)args->arg4, args->arg5);
		break;

		case __NR_chdir:
			ret = handle_chdir((const char *)args->arg1);
		break;

		case __NR_fchdir:
			ret = handle_fchdir(args->arg1);
		break;

		case __NR_exit:
			ret = handle_exit(args->arg1);
		break;

		case __NR_exit_group:
			ret = handle_exit_group(args->arg1);
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

static int bottom_open(Context *ctx, const This *this, const CallOpen *call) {
	int ret;
	RetInt *_ret = call->ret;

	if (call->at) {
		ret = __sysret(sys_openat(call->dirfd, call->path, call->flags, call->mode));
	} else {
		ret = __sysret(sys_open(call->path, call->flags, call->mode));
	}

	if (ret < 0) {
		_ret->_errno = errno;
	}
	_ret->ret = ret;
	return ret;
}

static int bottom_stat(Context *ctx, const This *this, const CallStat *call) {
	int ret;
	RetInt *_ret = call->ret;

	switch (call->type) {
		case STATTYPE_PLAIN:
			ret = __sysret(sys_stat(call->path, call->statbuf));
		break;

		case STATTYPE_F:
			ret = __sysret(sys_fstat(call->dirfd, call->statbuf));
		break;

		case STATTYPE_L:
			ret = __sysret(sys_lstat(call->path, call->statbuf));
		break;

		case STATTYPE_AT:
			ret = __sysret(sys_newfstatat(call->dirfd, call->path,
										  call->statbuf, call->flags));
		break;

		case STATTYPE_X:
			ret = __sysret(sys_statx(call->dirfd, call->path, call->flags,
									 call->mask, call->statbuf));
		break;

		default:
			abort();
		break;
	}

	if (ret < 0) {
		_ret->_errno = errno;
	}
	_ret->ret = ret;
	return ret;
}

static ssize_t bottom_readlink(Context *ctx, const This *this,
							   const CallReadlink *call) {
	ssize_t ret;
	RetSSize *_ret = call->ret;

	if (call->at) {
		ret = __sysret(sys_readlinkat(call->dirfd, call->path, call->buf,
									  call->bufsiz));
	} else {
		ret = __sysret(sys_readlink(call->path, call->buf, call->bufsiz));
	}

	if (ret < 0) {
		_ret->_errno = errno;
	}
	_ret->ret = ret;
	return ret;
}

static int bottom_access(Context *ctx, const This *this,
						 const CallAccess *call) {
	int ret;
	RetInt *_ret = call->ret;

	if (call->at) {
		ret = __sysret(sys_faccessat(call->dirfd, call->path, call->mode));
	} else {
		ret = __sysret(sys_access(call->path, call->mode));
	}

	if (ret < 0) {
		_ret->_errno = errno;
	}
	_ret->ret = ret;
	return ret;
}

static int _bottom_exec(Context *ctx, const This *this, CallExec *call) {
	int ret;
	int64_t argc;

	if (call->at && call->path[0] != '/') {
		exit_error("execveat with relative path");
	}

	argc = array_len(call->argv);
	if (argc >= INT_MAX -1) {
		errno = E2BIG;
		return -1;
	}

	char *new_argv[argc > 1 ? 2 + argc : 3];
	new_argv[0] = (char *) "loader_recurse";
	new_argv[1] = (char *) call->path;
	if (argc > 1) {
		array_copy(new_argv + 2, call->argv + 1, argc);
	} else {
		new_argv[2] = NULL;
	}
	call->path = PREFIX "/opt/loader";
	call->argv = new_argv;

	// TODO: What if execve fails?
	thread_exit();
	ctx->tls = NULL;

	// TODO: Properly emulate execveat
	ret = __sysret(sys_execve(call->path, call->argv, call->envp));

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int line_size(char *buf, ssize_t size) {
	for (int i = 0; i < size; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			return i + 1;
		}
	}

	errno = ENOEXEC;
	return -1;
}

static int read_header(char *out, size_t out_len, int fd) {
	ssize_t ret;
	const size_t scratch_size = (12*1024);
	char scratch[scratch_size];

	if (out && !out_len) {
		abort();
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0) {
		return -1;
	}

	if (out) {
		ret = read_full(fd, out, out_len);
		if (ret < 0) {
			return -1;
		}

		out[ret -1] = '\0';
		return ret;
	} else {
		ret = read_full(fd, scratch, scratch_size);
		if (ret < 0) {
			return -1;
		}

		if (ret < 2) {
			errno = ENOEXEC;
			return -1;
		}

		if (scratch[0] == '#' && scratch[1] == '!') {
			ret = line_size(scratch, scratch_size);
			if (ret < 0) {
				return -1;
			}
		} else {
			ret = 0;
		}

		return max(ret, (ssize_t)sizeof(Elf_Ehdr)) +1;
	}
}

static int bottom_exec(Context *ctx, const This *this,
					   const CallExec *call) {
	int fd;
	ssize_t ret, size;
	RetInt *_ret = call->ret;
	int64_t exec_argc;
	CallExec _call;
	callexec_copy(&_call, call);

	if (0) {
out:
		return _ret->ret;
	}

	if (call->final || (call->at && call->path[0] != '/')) {
		return _bottom_exec(ctx, this, &_call);
	}

	exec_argc = array_len(call->argv);
	if (exec_argc < 0) {
		_ret->_errno = E2BIG;
		_ret->ret = -1;
		goto out;
	}

	ret = access(call->path, X_OK);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		goto out;
	}

	fd = open(call->path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		goto out;
	}

	ret = read_header(NULL, 0, fd);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		close(fd);
		goto out;
	}
	size = ret;

	char header[size];
	ret = read_header(header, size, fd);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		close(fd);
		goto out;
	}
	close(fd);

	if (header[0] == '#' && header[1] == '!') {
		int sh_argc = cmdline_argc(header, size);
		if (sh_argc == 0) {
			_ret->_errno = ENOEXEC;
			_ret->ret = -1;
			goto out;
		}

		int64_t argc = exec_argc + sh_argc;
		char *argv[argc +1];

		cmdline_extract(header, size, argv);
		array_copy(argv + sh_argc, call->argv, exec_argc);
		argv[sh_argc] = (char *) call->path;
		argv[argc] = NULL;
		const char *pathname = argv[0];

		debug_exec(pathname, argv, call->envp);

		_call.path = pathname;
		_call.argv = argv;

		return _next->exec(ctx, _next->exec_next, &_call);
	}

	if ((size_t)size < sizeof(Elf_Ehdr) || !check_ehdr((Elf_Ehdr*)header)) {
		_ret->_errno = ENOEXEC;
		_ret->ret = -1;
		goto out;
	}

	_call.final = 1;
	_next->exec(ctx, _next->exec_next, &_call);

	return _ret->ret;
}

static int bottom_link(Context *ctx, const This *this, const CallLink *call) {
	int ret;
	RetInt *_ret = call->ret;

	if (call->at) {
		ret = __sysret(sys_linkat(call->olddirfd, call->oldpath, call->newdirfd,
								  call->newpath, call->flags));
	} else {
		ret = __sysret(sys_link(call->oldpath, call->newpath));
	}

	if (ret < 0) {
		_ret->_errno = errno;
	}
	_ret->ret = ret;
	return ret;
}

static int bottom_symlink(Context *ctx, const This *this,
						  const CallLink *call) {
	int ret;

	if (call->at) {
		ret = __sysret(sys_symlinkat(call->oldpath, call->newdirfd,
									 call->newpath));
	} else {
		ret = __sysret(sys_symlink(call->oldpath, call->newpath));
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_unlink(Context *ctx, const This *this,
						 const CallUnlink *call) {
	int ret;

	if (call->at) {
		ret = __sysret(sys_unlinkat(call->dirfd, call->path, call->flags));
	} else {
		ret = __sysret(sys_unlink(call->path));
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_setxattr(Context *ctx, const This *this,
						   const CallXattr *call) {
	int ret;

	switch (call->type2) {
		case XATTRTYPE_PLAIN:
			ret = __sysret(sys_setxattr(call->path, call->name,
										call->value, call->size, call->flags));
		break;

		case XATTRTYPE_L:
			ret = __sysret(sys_lsetxattr(call->path, call->name,
										 call->value, call->size, call->flags));
		break;

		case XATTRTYPE_F:
			ret = __sysret(sys_fsetxattr(call->fd, call->name,
										 call->value, call->size, call->flags));
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static ssize_t bottom_getxattr(Context *ctx, const This *this,
							   const CallXattr *call) {
	ssize_t ret;

	switch (call->type2) {
		case XATTRTYPE_PLAIN:
			ret = __sysret(sys_getxattr(call->path, call->name,
										call->value, call->size));
		break;

		case XATTRTYPE_L:
			ret = __sysret(sys_lgetxattr(call->path, call->name,
										 call->value, call->size));
		break;

		case XATTRTYPE_F:
			ret = __sysret(sys_fgetxattr(call->fd, call->name,
										 call->value, call->size));
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static ssize_t bottom_listxattr(Context *ctx, const This *this,
								const CallXattr *call) {
	ssize_t ret;

	switch (call->type2) {
		case XATTRTYPE_PLAIN:
			ret = __sysret(sys_listxattr(call->path, call->list, call->size));
		break;

		case XATTRTYPE_L:
			ret = __sysret(sys_llistxattr(call->path, call->list, call->size));
		break;

		case XATTRTYPE_F:
			ret = __sysret(sys_flistxattr(call->fd, call->list, call->size));
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_removexattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	int ret;

	switch (call->type2) {
		case XATTRTYPE_PLAIN:
			ret = __sysret(sys_removexattr(call->path, call->name));
		break;

		case XATTRTYPE_L:
			ret = __sysret(sys_lremovexattr(call->path, call->name));
		break;

		case XATTRTYPE_F:
			ret = __sysret(sys_fremovexattr(call->fd, call->name));
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static ssize_t bottom_xattr(Context *ctx, const This *this,
							const CallXattr *call) {
	switch (call->type) {
		case XATTRTYPE_SET:
			return bottom_setxattr(ctx, this, call);
		break;

		case XATTRTYPE_GET:
			return bottom_getxattr(ctx, this, call);
		break;

		case XATTRTYPE_LIST:
			return bottom_listxattr(ctx, this, call);
		break;

		case XATTRTYPE_REMOVE:
			return bottom_removexattr(ctx, this, call);
		break;

		default:
			abort();
		break;
	}
}

static int bottom_rename(Context *ctx, const This *this,
						 const CallRename *call) {
	int ret;

	switch (call->type) {
		case RENAMETYPE_PLAIN:
			ret = __sysret(sys_rename(call->oldpath, call->newpath));
		break;

		case RENAMETYPE_AT:
			ret = __sysret(sys_renameat(call->olddirfd, call->oldpath,
										call->newdirfd, call->newpath));
		break;

		case RENAMETYPE_AT2:
			ret = __sysret(sys_renameat2(call->olddirfd, call->oldpath,
										 call->newdirfd, call->newpath, call->flags));
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static const CallHandler bottom = {
	bottom_open,
	NULL,
	bottom_stat,
	NULL,
	bottom_readlink,
	NULL,
	bottom_access,
	NULL,
	bottom_exec,
	NULL,
	bottom_link,
	NULL,
	bottom_symlink,
	NULL,
	bottom_unlink,
	NULL,
	bottom_xattr,
	NULL,
	bottom_rename,
	NULL
};
