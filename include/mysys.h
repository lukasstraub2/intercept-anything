#pragma once

#include "sys.h"
#include "asm-generic/posix_types.h"

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
#ifdef __NR_stat
	return my_syscall2(__NR_stat, path, statbuf);
#else
	return __nolibc_enosys(__func__, path, statbuf);
#endif
}

static __attribute__((unused))
int sys_fstat(int fd, void *statbuf) {
	return my_syscall2(__NR_fstat, fd, statbuf);
}

static __attribute__((unused))
int sys_lstat(const char *path, void *statbuf) {
#ifdef __NR_lstat
	return my_syscall2(__NR_lstat, path, statbuf);
#else
	return __nolibc_enosys(__func__, path, statbuf);
#endif
}

static __attribute__((unused))
int sys_newfstatat(int dirfd, const char *path, void *statbuf, int flags) {
	return my_syscall4(__NR_newfstatat, dirfd, path, statbuf, flags);
}

static __attribute__((unused))
ssize_t sys_readlink(const char *path, char *buf, unsigned long bufsiz) {
#ifdef __NR_readlink
	return my_syscall3(__NR_readlink, path, buf, bufsiz);
#else
	return my_syscall4(__NR_readlinkat, AT_FDCWD, path, buf, bufsiz);
#endif
}

static __attribute__((unused))
ssize_t sys_readlinkat(int dirfd, const char *path, char *buf,
					   unsigned long bufsiz) {
	return my_syscall4(__NR_readlinkat, dirfd, path, buf, bufsiz);
}

static __attribute__((unused))
int sys_faccessat(int dirfd, const char *path, int mode) {
	return my_syscall3(__NR_faccessat, dirfd, path, mode);
}

static __attribute__((unused))
int sys_access(const char *path, int mode) {
#ifdef __NR_access
	return my_syscall2(__NR_access, path, mode);
#else
	return my_syscall3(__NR_faccessat, AT_FDCWD, path, mode);
#endif
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
int sys_rt_sigaction(int signum, const struct sigaction *act,
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
int sys_unlinkat(int dirfd, const char *pathname, int flags) {
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
#ifdef __NR_rename
	return my_syscall2(__NR_rename, oldpath, newpath);
#else
	return my_syscall4(__NR_renameat, AT_FDCWD, oldpath, AT_FDCWD, newpath);
#endif
}

static __attribute__((unused))
int sys_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
	return my_syscall4(__NR_renameat, olddirfd, oldpath, newdirfd, newpath);
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
int sys_flock(int fd, int operation) {
	return my_syscall2(__NR_flock, fd, operation);
}

static __attribute__((unused))
signed long sys_futex(uint32_t *uaddr, int futex_op, uint32_t val,
					  const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3) {
	return my_syscall6(__NR_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

static __attribute__((noreturn,unused))
void sys_exit_group(int status)
{
	my_syscall1(__NR_exit_group, status & 255);
	while(1);
}

static __attribute__((unused))
int sys_fchmod(int fd, mode_t mode)
{
	return my_syscall2(__NR_fchmod, fd, mode);
}

static __attribute__((unused))
int sys_fchmodat(int dirfd, const char *path, mode_t mode)
{
	return my_syscall3(__NR_fchmodat, dirfd, path, mode);
}

static __attribute__((unused))
int sys_truncate(const char *path, off_t length)
{
	return my_syscall2(__NR_truncate, path, length);
}

static __attribute__((unused))
int sys_ftruncate(int fd, off_t length)
{
	return my_syscall2(__NR_ftruncate, fd, length);
}

static __attribute__((unused))
int sys_mkdirat(int dirfd, const char *path, mode_t mode)
{
	return my_syscall3(__NR_mkdirat, dirfd, path, mode);
}

static __attribute__((unused))
int sys_getdents(int fd, void *dirp, int count)
{
#ifdef __NR_getdents
	return my_syscall3(__NR_getdents, fd, dirp, count);
#else
	return __nolibc_enosys(__func__, fd, dirp, count);
#endif
}

static __attribute__((unused))
long sys_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
{
	return my_syscall4(__NR_mknodat, dirfd, path, mode, dev);
}

static __attribute__((unused))
int sys_accept(int fd, void *addr, int *addrlen) {
	return my_syscall3(__NR_accept, fd, addr, addrlen);
}

static __attribute__((unused))
int sys_accept4(int fd, void *addr, int *addrlen, int flags) {
	return my_syscall4(__NR_accept4, fd, addr, addrlen, flags);
}

static __attribute__((unused))
int sys_bind(int fd, void *addr, int addrlen) {
	return my_syscall3(__NR_bind, fd, addr, addrlen);
}

static __attribute__((unused))
int sys_connect(int fd, void *addr, int addrlen) {
	return my_syscall3(__NR_connect, fd, addr, addrlen);
}

static __attribute__((unused))
int sys_fanotify_mark(int fanotify_fd, unsigned int flags,
					  __u64 mask, int dfd, const char *pathname) {
	return my_syscall5(__NR_fanotify_mark, fanotify_fd, flags, mask, dfd, pathname);
}

static __attribute__((unused))
int sys_inotify_add_watch(int fd, const char *pathname, __u32 mask) {
	return my_syscall3(__NR_inotify_add_watch, fd, pathname, mask);
}

static __attribute__((unused))
int sys_getrlimit(unsigned int resource, void *rlim) {
	return my_syscall2(__NR_getrlimit, resource, rlim);
}

static __attribute__((unused))
int sys_setrlimit(unsigned int resource, const void *rlim) {
	return my_syscall2(__NR_setrlimit, resource, rlim);
}

static __attribute__((unused))
int sys_tgkill(pid_t tgid, pid_t tid, int sig) {
	return my_syscall3(__NR_tgkill, tgid, tid, sig);
}

static __attribute__((unused))
int sys_tkill(pid_t tid, int sig) {
	return my_syscall2(__NR_tkill, tid, sig);
}

static __attribute__((unused))
ssize_t sys_splice(int fd_in, __kernel_loff_t *off_in,
				   int fd_out, __kernel_loff_t *off_out,
				   size_t len, unsigned int flags) {
	return my_syscall6(__NR_splice, fd_in, off_in, fd_out, off_out, len, flags);
}

static __attribute__((unused))
int sys_madvise(void *start, size_t len_in, int behavior) {
	return my_syscall3(__NR_madvise, start, len_in, behavior);
}

static __attribute__((unused))
long sys_ptrace(long request, long pid, void *addr, void *data) {
	return my_syscall4(__NR_ptrace, request, pid, addr, data);
}

static __attribute__((unused))
int sys_close_range(unsigned int fd, unsigned int max_fd, unsigned int flags) {
#ifdef __NR_close_range
	return my_syscall3(__NR_close_range, fd, max_fd, flags);
#else
	return __nolibc_enosys(__func__, fd, max_fd, flags);
#endif
}
