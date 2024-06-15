
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
	return my_syscall2(__NR_access, path, mode);
}

static int handle_access(const char *path, int mode) {
	trace("access(%s)\n", path);
	return __sysret(sys_access(path, mode));
}

static int handle_execve(const char *path, char *const argv[], char *const envp[]) {
	trace("execve(%s)\n", path);

	int64_t argc;

	argc = array_len(argv);
	if (argc >= INT_MAX -1) {
		errno = E2BIG;
		return -1;
	}

	char *new_argv[argc > 1 ? 2 + argc : 3];
	new_argv[0] = (char *) "loader_recurse";
	new_argv[1] = (char *) path;
	if (argc > 1) {
		array_copy(new_argv + 2, argv + 1, argc);
	} else {
		new_argv[2] = NULL;
	}

	return __sysret(sys_execve("/home/lukas/rootlink/loader", new_argv, envp));
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

static int handle_link(const char *oldpath, const char *newpath) {
	trace("link(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_link(oldpath, newpath));
}

static int sys_linkat(int olddirfd, const char *oldpath, int newdirfd,
					  const char *newpath, int flags) {
	return my_syscall5(__NR_linkat, olddirfd, oldpath, newdirfd, newpath, flags);
}

static int handle_linkat(int olddirfd, const char *oldpath, int newdirfd,
						 const char *newpath, int flags) {
	trace("linkat(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_linkat(olddirfd, oldpath, newdirfd, newpath, flags));
}

static int handle_symlink(const char *oldpath, const char *newpath) {
	trace("symlink(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_symlink(oldpath, newpath));
}

static int sys_symlinkat(const char *oldpath, int newdirfd,
						 const char *newpath) {
	return my_syscall3(__NR_symlinkat, oldpath, newdirfd, newpath);
}

static int handle_symlinkat(const char *oldpath, int newdirfd,
							const char *newpath) {
	trace("symlinkat(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_symlinkat(oldpath, newdirfd, newpath));
}

static int handle_unlink(const char *pathname) {
	trace("unlink(%s)\n", pathname);
	return __sysret(sys_unlink(pathname));
}

static int sys_unlinkat(int dirfd, const char *pathname, int flags) {
	return my_syscall3(__NR_unlinkat, dirfd, pathname, flags);
}

static int handle_unlinkat(int dirfd, const char *pathname, int flags) {
	trace("unlinkat(%s)\n", pathname);
	return __sysret(sys_unlinkat(dirfd, pathname, flags));
}

static int sys_setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	return my_syscall5(__NR_setxattr, path, name, value, size, flags);
}

static int handle_setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	trace("setxattr(%s, %s)\n", path, name);
	return __sysret(sys_setxattr(path, name, value, size, flags));
}

static int sys_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	return my_syscall5(__NR_lsetxattr, path, name, value, size, flags);
}

static int handle_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	trace("lsetxattr(%s, %s)\n", path, name);
	return __sysret(sys_lsetxattr(path, name, value, size, flags));
}

static int sys_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
	return my_syscall5(__NR_fsetxattr, fd, name, value, size, flags);
}

static int handle_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
	trace("fsetxattr(%d, %s)\n", fd, name);
	return __sysret(sys_fsetxattr(fd, name, value, size, flags));
}

static ssize_t sys_getxattr(const char *path, const char *name, void *value, size_t size) {
	return my_syscall4(__NR_getxattr, path, name, value, size);
}

static ssize_t handle_getxattr(const char *path, const char *name, void *value, size_t size) {
	trace("getxattr(%s, %s)\n", path, name);
	return __sysret(sys_getxattr(path, name, value, size));
}

static ssize_t sys_lgetxattr(const char *path, const char *name, void *value, size_t size) {
	return my_syscall4(__NR_lgetxattr, path, name, value, size);
}

static ssize_t handle_lgetxattr(const char *path, const char *name, void *value, size_t size) {
	trace("lgetxattr(%s, %s)\n", path, name);
	return __sysret(sys_lgetxattr(path, name, value, size));
}

static ssize_t sys_fgetxattr(int fd, const char *name, void *value, size_t size) {
	return my_syscall4(__NR_fgetxattr, fd, name, value, size);
}

static ssize_t handle_fgetxattr(int fd, const char *name, void *value, size_t size) {
	trace("fgetxattr(%d, %s)\n", fd, name);
	return __sysret(sys_fgetxattr(fd, name, value, size));
}

static ssize_t sys_listxattr(const char *path, char *list, size_t size) {
	return my_syscall3(__NR_listxattr, path, list, size);
}

static ssize_t handle_listxattr(const char *path, char *list, size_t size) {
	trace("listxattr(%s)\n", path);
	return __sysret(sys_listxattr(path, list, size));
}

static ssize_t sys_llistxattr(const char *path, char *list, size_t size) {
	return my_syscall3(__NR_llistxattr, path, list, size);
}

static ssize_t handle_llistxattr(const char *path, char *list, size_t size) {
	trace("llistxattr(%s)\n", path);
	return __sysret(sys_llistxattr(path, list, size));
}


static ssize_t sys_flistxattr(int fd, char *list, size_t size) {
	return my_syscall3(__NR_flistxattr, fd, list, size);
}

static ssize_t handle_flistxattr(int fd, char *list, size_t size) {
	trace("flistxattr(%d)\n", fd);
	return __sysret(sys_flistxattr(fd, list, size));
}

static int sys_removexattr(const char *path, const char *name) {
	return my_syscall2(__NR_removexattr, path, name);
}

static int handle_removexattr(const char *path, const char *name) {
	trace("removexattr(%s, %s)\n", path, name);
	return __sysret(sys_removexattr(path, name));
}

static int sys_lremovexattr(const char *path, const char *name) {
	return my_syscall2(__NR_lremovexattr, path, name);
}

static int handle_lremovexattr(const char *path, const char *name) {
	trace("lremovexattr(%s, %s)\n", path, name);
	return __sysret(sys_lremovexattr(path, name));
}

static int sys_fremovexattr(int fd, const char *name) {
	return my_syscall2(__NR_fremovexattr, fd, name);
}

static int handle_fremovexattr(int fd, const char *name) {
	trace("fremovexattr(%d, %s)\n", fd, name);
	return __sysret(sys_fremovexattr(fd, name));
}

static int sys_rename(const char *oldpath, const char *newpath) {
	return my_syscall2(__NR_rename, oldpath, newpath);
}

static int handle_rename(const char *oldpath, const char *newpath) {
	trace("rename(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_rename(oldpath, newpath));
}

static int sys_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
	return my_syscall4(__NR_renameat, olddirfd, oldpath, newdirfd, newpath);
}

static int handle_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
	trace("renameat(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_renameat(olddirfd, oldpath, newdirfd, newpath));
}

static int sys_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
	return my_syscall5(__NR_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}

static int handle_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
	trace("renameat2(%s, %s)\n", oldpath, newpath);
	return __sysret(sys_renameat2(olddirfd, oldpath, newdirfd, newpath, flags));
}

static int handle_chdir(const char *path) {
	trace("chdir(%s)\n", path);
	return __sysret(sys_chdir(path));
}

static int sys_fchdir(int fd) {
	return my_syscall1(__NR_fchdir, fd);
}

static int handle_fchdir(int fd) {
	trace("fchdir(%d)\n", fd);
	return __sysret(sys_fchdir(fd));
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
										(sigset_t *)args->arg3, args->arg4,
										ucontext);
		break;

		case __NR_rt_sigaction:
			ret = handle_rt_sigaction(args->arg1,
									  (const struct sigaction *)args->arg2,
									  (struct sigaction *)args->arg3, args->arg4);
		break;

		case __NR_link:
			ret = handle_link((const char *)args->arg1, (const char *)args->arg2);
		break;

		case __NR_linkat:
			ret = handle_linkat(args->arg1, (const char *)args->arg2, args->arg3,
								(const char *)args->arg4, args->arg5);
		break;

		case __NR_symlink:
			ret = handle_symlink((const char *)args->arg1,
								 (const char *)args->arg2);
		break;

		case __NR_symlinkat:
			ret = handle_symlinkat((const char *)args->arg1, args->arg2,
								   (const char *)args->arg3);
		break;

		case __NR_unlink:
			ret = handle_unlink((const char *)args->arg1);
		break;

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

		case __NR_rename:
			ret = handle_rename((const char *)args->arg1, (const char *)args->arg2);
		break;

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
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_chdir, 38, 1),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fchdir, 37, 1),
#ifdef __NR_open
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 36, 0),
#else
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 36, 0),
#endif
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 35, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_stat, 34, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_fstat, 33, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_lstat, 32, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_newfstatat, 31, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_statx, 30, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlink, 29, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_readlinkat, 28, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_access, 27, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_faccessat, 26, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execve, 25, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_execveat, 24, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigprocmask, 23, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigaction, 22, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_link, 21, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_linkat, 20, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlink, 19, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_symlinkat, 18, 0),
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_unlink, 17, 0),
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
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rename, 3, 0),
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

static void unblock_sigsys() {
	sigset_t unblock = (1u << (SIGSYS -1));
	sys_rt_sigprocmask(SIG_UNBLOCK, &unblock, NULL, sizeof(sigset_t));
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
	sig.sa_flags = SA_SIGINFO;

	sigaction(SIGSYS, &sig, NULL);
	unblock_sigsys();
	trace("registered signal handler\n");

	if (!recursing) {
		install_filter();
	}
}
