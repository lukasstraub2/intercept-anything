#pragma once

#include "sys.h"

static __attribute__((unused))
int sys_openat(int dirfd, const char *path, int flags, mode_t mode) {
#ifdef __NR_openat
	return my_syscall4(__NR_openat, dirfd, path, flags, mode);
#else
	return __nolibc_enosys(__func__, path, flags, mode);
#endif
}

static __attribute__((unused))
int sys_stat(const char *path, void *statbuf) {
	return my_syscall2(__NR_stat, path, statbuf);
}

static __attribute__((unused))
int sys_fstat(int fd, void *statbuf) {
	return my_syscall2(__NR_fstat, fd, statbuf);
}

static __attribute__((unused))
int sys_lstat(const char *path, void *statbuf) {
	return my_syscall2(__NR_lstat, path, statbuf);
}

static __attribute__((unused))
int sys_newfstatat(int dirfd, const char *path, void *statbuf, int flags) {
	return my_syscall4(__NR_newfstatat, dirfd, path, statbuf, flags);
}

static __attribute__((unused))
ssize_t sys_readlink(const char *path, char *buf, unsigned long bufsiz) {
	return my_syscall3(__NR_readlink, path, buf, bufsiz);
}

static __attribute__((unused))
ssize_t readlink(const char *path, char *buf, unsigned long bufsiz) {
	return __sysret(sys_readlink(path, buf, bufsiz));
}

static __attribute__((unused))
ssize_t sys_readlinkat(int dirfd, const char *path, char *buf,
					   unsigned long bufsiz) {
	return my_syscall4(__NR_readlinkat, dirfd, path, buf, bufsiz);
}

static __attribute__((unused))
ssize_t readlinkat(int dirfd, const char *path, char *buf,
				   unsigned long bufsiz) {
	return __sysret(sys_readlinkat(dirfd, path, buf, bufsiz));
}

static __attribute__((unused))
int sys_faccessat(int dirfd, const char *path, int mode) {
	return my_syscall3(__NR_faccessat, dirfd, path, mode);
}

static __attribute__((unused))
int sys_access(const char *path, int mode) {
	return my_syscall2(__NR_access, path, mode);
}

static __attribute__((unused))
int access(const char *path, int mode) {
	return __sysret(sys_access(path, mode));
}

static __attribute__((unused))
int sys_execveat(int dirfd, const char *path, char *const argv[],
				 char *const envp[], int flags) {
	return my_syscall5(__NR_execveat, dirfd, path, argv, envp, flags);
}

static __attribute__((unused))
int sys_rt_sigprocmask(int how, const sigset_t *set,
					   sigset_t *oldset, size_t sigsetsize) {
	return my_syscall4(__NR_rt_sigprocmask, how, set, oldset, sigsetsize);
}

static __attribute__((unused))
long sys_rt_sigaction(int signum, const struct sigaction *act,
					  struct sigaction *oldact, size_t sigsetsize) {
	return my_syscall4(__NR_rt_sigaction, signum, act, oldact, sigsetsize);
}

static __attribute__((unused))
int sys_linkat(int olddirfd, const char *oldpath, int newdirfd,
				const char *newpath, int flags) {
	return my_syscall5(__NR_linkat, olddirfd, oldpath, newdirfd, newpath, flags);
}

static __attribute__((unused))
int sys_symlinkat(const char *oldpath, int newdirfd, const char *newpath) {
	return my_syscall3(__NR_symlinkat, oldpath, newdirfd, newpath);
}

static __attribute__((unused))
int symlinkat(const char *oldpath, int newdirfd, const char *newpath) {
	return __sysret(sys_symlinkat(oldpath, newdirfd, newpath));
}

static __attribute__((unused)) int sys_unlinkat(int dirfd, const char *pathname, int flags) {
	return my_syscall3(__NR_unlinkat, dirfd, pathname, flags);
}

static __attribute__((unused))
int sys_setxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	return my_syscall5(__NR_setxattr, path, name, value, size, flags);
}

static __attribute__((unused))
int sys_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags) {
	return my_syscall5(__NR_lsetxattr, path, name, value, size, flags);
}

static __attribute__((unused))
int sys_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags) {
	return my_syscall5(__NR_fsetxattr, fd, name, value, size, flags);
}

static __attribute__((unused))
ssize_t sys_getxattr(const char *path, const char *name, void *value, size_t size) {
	return my_syscall4(__NR_getxattr, path, name, value, size);
}

static __attribute__((unused))
ssize_t sys_lgetxattr(const char *path, const char *name, void *value, size_t size) {
	return my_syscall4(__NR_lgetxattr, path, name, value, size);
}

static __attribute__((unused))
ssize_t sys_fgetxattr(int fd, const char *name, void *value, size_t size) {
	return my_syscall4(__NR_fgetxattr, fd, name, value, size);
}

static __attribute__((unused))
ssize_t sys_listxattr(const char *path, char *list, size_t size) {
	return my_syscall3(__NR_listxattr, path, list, size);
}

static __attribute__((unused))
ssize_t sys_llistxattr(const char *path, char *list, size_t size) {
	return my_syscall3(__NR_llistxattr, path, list, size);
}

static __attribute__((unused))
ssize_t sys_flistxattr(int fd, char *list, size_t size) {
	return my_syscall3(__NR_flistxattr, fd, list, size);
}

static __attribute__((unused))
int sys_removexattr(const char *path, const char *name) {
	return my_syscall2(__NR_removexattr, path, name);
}

static __attribute__((unused))
int sys_lremovexattr(const char *path, const char *name) {
	return my_syscall2(__NR_lremovexattr, path, name);
}

static __attribute__((unused))
int sys_fremovexattr(int fd, const char *name) {
	return my_syscall2(__NR_fremovexattr, fd, name);
}

static __attribute__((unused))
int sys_rename(const char *oldpath, const char *newpath) {
	return my_syscall2(__NR_rename, oldpath, newpath);
}

static __attribute__((unused))
int rename(const char *oldpath, const char *newpath) {
	return __sysret(sys_rename(oldpath, newpath));
}

static __attribute__((unused))
int sys_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
	return my_syscall4(__NR_renameat, olddirfd, oldpath, newdirfd, newpath);
}

static __attribute__((unused))
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
	return __sysret(sys_renameat(olddirfd, oldpath, newdirfd, newpath));
}

static __attribute__((unused))
int sys_renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
	return my_syscall5(__NR_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}

static __attribute__((unused))
int sys_fchdir(int fd) {
	return my_syscall1(__NR_fchdir, fd);
}

static __attribute__((unused))
int sys_getcwd(char *buf, size_t size) {
	return my_syscall2(__NR_getcwd, buf, size);
}

static __attribute__((unused))
int getcwd(char *buf, size_t size) {
	return __sysret(sys_getcwd(buf, size));
}

static __attribute__((unused))
int sys_flock(int fd, int operation) {
	return my_syscall2(__NR_flock, fd, operation);
}

static __attribute__((unused))
int flock(int fd, int operation) {
	return __sysret(sys_flock(fd, operation));
}
