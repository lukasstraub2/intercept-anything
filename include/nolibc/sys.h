/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Syscall definitions for NOLIBC (those in man(2))
 * Copyright (C) 2017-2021 Willy Tarreau <w@1wt.eu>
 */

#ifndef _NOLIBC_SYS_H
#define _NOLIBC_SYS_H

#include "arch.h"

#include <sys/select.h>
#include <sys/types.h>
#include <errno.h>
#include <syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <elf.h>
#include <stddef.h>

/* Syscall ENOSYS helper: Avoids unused-parameter warnings and provides a
 * debugging hook.
 */

static __inline__ int __nolibc_enosys(const char *syscall, ...)
{
	(void)syscall;
	return -ENOSYS;
}


/* Functions in this file only describe syscalls. They're declared static so
 * that the compiler usually decides to inline them while still being allowed
 * to pass a pointer to one of their instances. Each syscall exists in two
 * versions:
 *   - the "internal" ones, which matches the raw syscall interface at the
 *     kernel level, which may sometimes slightly differ from the documented
 *     libc-level ones. For example most of them return either a valid value
 *     or -errno. All of these are prefixed with "sys_". They may be called
 *     by non-portable applications if desired.
 *
 *   - the "exported" ones, whose interface must closely match the one
 *     documented in man(2), that applications are supposed to expect. These
 *     ones rely on the internal ones, and set errno.
 *
 * Each syscall will be defined with the two functions, sorted in alphabetical
 * order applied to the exported names.
 *
 * In case of doubt about the relevance of a function here, only those which
 * set errno should be defined here. Wrappers like those appearing in man(3)
 * should not be placed here.
 */


/*
 * int brk(void *addr);
 * void *sbrk(intptr_t inc)
 */

static __attribute__((unused))
void *sys_brk(void *addr)
{
	return (void *)my_syscall1(__NR_brk, addr);
}

/*
 * int chdir(const char *path);
 */

static __attribute__((unused))
int sys_chdir(const char *path)
{
	return my_syscall1(__NR_chdir, path);
}

/*
 * int chmod(const char *path, mode_t mode);
 */

static __attribute__((unused))
int sys_chmod(const char *path, mode_t mode)
{
#ifdef __NR_fchmodat
	return my_syscall4(__NR_fchmodat, AT_FDCWD, path, mode, 0);
#elif defined(__NR_chmod)
	return my_syscall2(__NR_chmod, path, mode);
#else
	return __nolibc_enosys(__func__, path, mode);
#endif
}

/*
 * int chown(const char *path, uid_t owner, gid_t group);
 */

static __attribute__((unused))
int sys_chown(const char *path, uid_t owner, gid_t group)
{
#ifdef __NR_fchownat
	return my_syscall5(__NR_fchownat, AT_FDCWD, path, owner, group, 0);
#elif defined(__NR_chown)
	return my_syscall3(__NR_chown, path, owner, group);
#else
	return __nolibc_enosys(__func__, path, owner, group);
#endif
}

/*
 * int chroot(const char *path);
 */

static __attribute__((unused))
int sys_chroot(const char *path)
{
	return my_syscall1(__NR_chroot, path);
}

/*
 * int close(int fd);
 */

static __attribute__((unused))
int sys_close(int fd)
{
	return my_syscall1(__NR_close, fd);
}

/*
 * int dup(int fd);
 */

static __attribute__((unused))
int sys_dup(int fd)
{
	return my_syscall1(__NR_dup, fd);
}

/*
 * int dup2(int old, int new);
 */

static __attribute__((unused))
int sys_dup2(int from, int to)
{
#ifdef __NR_dup3
	return my_syscall3(__NR_dup3, from, to, 0);
#elif defined(__NR_dup2)
	return my_syscall2(__NR_dup2, from, to);
#else
	return __nolibc_enosys(__func__, from, to);
#endif
}

/*
 * int dup3(int old, int new, int flags);
 */

#ifdef __NR_dup3
static __attribute__((unused))
int sys_dup3(int from, int to, int flags)
{
	return my_syscall3(__NR_dup3, from, to, flags);
}
#endif


/*
 * int execve(const char *filename, char *const argv[], char *const envp[]);
 */

static __attribute__((unused))
int sys_execve(const char *filename, char *const argv[], char *const envp[])
{
	return my_syscall3(__NR_execve, filename, argv, envp);
}

/*
 * void exit(int status);
 */

static __attribute__((noreturn,unused))
void sys_exit(int status)
{
	my_syscall1(__NR_exit, status & 255);
	while(1); /* shut the "noreturn" warnings. */
}

/*
 * pid_t fork(void);
 */

#ifndef sys_fork
static __attribute__((unused))
pid_t sys_fork(void)
{
#ifdef __NR_clone
	/* note: some archs only have clone() and not fork(). Different archs
	 * have a different API, but most archs have the flags on first arg and
	 * will not use the rest with no other flag.
	 */
	return my_syscall5(__NR_clone, SIGCHLD, 0, 0, 0, 0);
#elif defined(__NR_fork)
	return my_syscall0(__NR_fork);
#else
	return __nolibc_enosys(__func__);
#endif
}
#endif

/*
 * int fsync(int fd);
 */

static __attribute__((unused))
int sys_fsync(int fd)
{
	return my_syscall1(__NR_fsync, fd);
}

/*
 * int getdents64(int fd, struct linux_dirent64 *dirp, int count);
 */

static __attribute__((unused))
int sys_getdents64(int fd, struct linux_dirent64 *dirp, int count)
{
	return my_syscall3(__NR_getdents64, fd, dirp, count);
}

/*
 * uid_t geteuid(void);
 */

static __attribute__((unused))
uid_t sys_geteuid(void)
{
#ifdef __NR_geteuid32
	return my_syscall0(__NR_geteuid32);
#else
	return my_syscall0(__NR_geteuid);
#endif
}

/*
 * pid_t getpgid(pid_t pid);
 */

static __attribute__((unused))
pid_t sys_getpgid(pid_t pid)
{
	return my_syscall1(__NR_getpgid, pid);
}

/*
 * pid_t getpgrp(void);
 */

static __attribute__((unused))
pid_t sys_getpgrp(void)
{
	return sys_getpgid(0);
}

/*
 * pid_t getpid(void);
 */

static __attribute__((unused))
pid_t sys_getpid(void)
{
	return my_syscall0(__NR_getpid);
}

/*
 * pid_t getppid(void);
 */

static __attribute__((unused))
pid_t sys_getppid(void)
{
	return my_syscall0(__NR_getppid);
}

/*
 * pid_t gettid(void);
 */

static __attribute__((unused))
pid_t sys_gettid(void)
{
	return my_syscall0(__NR_gettid);
}

/*
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 */

static __attribute__((unused))
int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
#ifdef __NR_gettimeofday
	return my_syscall2(__NR_gettimeofday, tv, tz);
#else
	return __nolibc_enosys(__func__, tv, tz);
#endif
}

/*
 * uid_t getuid(void);
 */

static __attribute__((unused))
uid_t sys_getuid(void)
{
#ifdef __NR_getuid32
	return my_syscall0(__NR_getuid32);
#else
	return my_syscall0(__NR_getuid);
#endif
}

/*
 * int ioctl(int fd, unsigned long req, void *value);
 */

static __attribute__((unused))
int sys_ioctl(int fd, unsigned long req, void *value)
{
	return my_syscall3(__NR_ioctl, fd, req, value);
}

/*
 * int kill(pid_t pid, int signal);
 */

static __attribute__((unused))
int sys_kill(pid_t pid, int signal)
{
	return my_syscall2(__NR_kill, pid, signal);
}

/*
 * int link(const char *old, const char *new);
 */

static __attribute__((unused))
int sys_link(const char *from, const char *to)
{
#ifdef __NR_linkat
	return my_syscall5(__NR_linkat, AT_FDCWD, from, AT_FDCWD, to, 0);
#elif defined(__NR_link)
	return my_syscall2(__NR_link, from, to);
#else
	return __nolibc_enosys(__func__, from, to);
#endif
}

/*
 * off_t lseek(int fd, off_t offset, int whence);
 */

static __attribute__((unused))
off_t sys_lseek(int fd, off_t offset, int whence)
{
#ifdef __NR_lseek
	return my_syscall3(__NR_lseek, fd, offset, whence);
#else
	return __nolibc_enosys(__func__, fd, offset, whence);
#endif
}

/*
 * int mkdir(const char *path, mode_t mode);
 */

static __attribute__((unused))
int sys_mkdir(const char *path, mode_t mode)
{
#ifdef __NR_mkdirat
	return my_syscall3(__NR_mkdirat, AT_FDCWD, path, mode);
#elif defined(__NR_mkdir)
	return my_syscall2(__NR_mkdir, path, mode);
#else
	return __nolibc_enosys(__func__, path, mode);
#endif
}

/*
 * int rmdir(const char *path);
 */

static __attribute__((unused))
int sys_rmdir(const char *path)
{
#ifdef __NR_rmdir
	return my_syscall1(__NR_rmdir, path);
#elif defined(__NR_unlinkat)
	return my_syscall3(__NR_unlinkat, AT_FDCWD, path, AT_REMOVEDIR);
#else
	return __nolibc_enosys(__func__, path);
#endif
}

/*
 * int mknod(const char *path, mode_t mode, dev_t dev);
 */

static __attribute__((unused))
long sys_mknod(const char *path, mode_t mode, dev_t dev)
{
#ifdef __NR_mknodat
	return my_syscall4(__NR_mknodat, AT_FDCWD, path, mode, dev);
#elif defined(__NR_mknod)
	return my_syscall3(__NR_mknod, path, mode, dev);
#else
	return __nolibc_enosys(__func__, path, mode, dev);
#endif
}

#ifndef sys_mmap
static __attribute__((unused))
void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd,
	       off_t offset)
{
	int n;

#if defined(__NR_mmap2)
	n = __NR_mmap2;
	offset >>= 12;
#else
	n = __NR_mmap;
#endif

	return (void *)my_syscall6(n, addr, length, prot, flags, fd, offset);
}
#endif

static __attribute__((unused))
int sys_munmap(void *addr, size_t length)
{
	return my_syscall2(__NR_munmap, addr, length);
}

/*
 * int mount(const char *source, const char *target,
 *           const char *fstype, unsigned long flags,
 *           const void *data);
 */
static __attribute__((unused))
int sys_mount(const char *src, const char *tgt, const char *fst,
                     unsigned long flags, const void *data)
{
	return my_syscall5(__NR_mount, src, tgt, fst, flags, data);
}

/*
 * int open(const char *path, int flags[, mode_t mode]);
 */

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

/*
 * int pipe2(int pipefd[2], int flags);
 * int pipe(int pipefd[2]);
 */

static __attribute__((unused))
int sys_pipe2(int pipefd[2], int flags)
{
	return my_syscall2(__NR_pipe2, pipefd, flags);
}

/*
 * int prctl(int option, unsigned long arg2, unsigned long arg3,
 *                       unsigned long arg4, unsigned long arg5);
 */

static __attribute__((unused))
int sys_prctl(int option, unsigned long arg2, unsigned long arg3,
		          unsigned long arg4, unsigned long arg5)
{
	return my_syscall5(__NR_prctl, option, arg2, arg3, arg4, arg5);
}

/*
 * int pivot_root(const char *new, const char *old);
 */

static __attribute__((unused))
int sys_pivot_root(const char *new_root, const char *put_old)
{
	return my_syscall2(__NR_pivot_root, new_root, put_old);
}

/*
 * int poll(struct pollfd *fds, int nfds, int timeout);
 */

static __attribute__((unused))
int sys_poll(struct pollfd *fds, int nfds, int timeout)
{
#if defined(__NR_ppoll)
	struct timespec t;

	if (timeout >= 0) {
		t.tv_sec  = timeout / 1000;
		t.tv_nsec = (timeout % 1000) * 1000000;
	}
	return my_syscall5(__NR_ppoll, fds, nfds, (timeout >= 0) ? &t : NULL, NULL, 0);
#elif defined(__NR_poll)
	return my_syscall3(__NR_poll, fds, nfds, timeout);
#else
	return __nolibc_enosys(__func__, fds, nfds, timeout);
#endif
}

/*
 * ssize_t read(int fd, void *buf, size_t count);
 */

static __attribute__((unused))
ssize_t sys_read(int fd, void *buf, size_t count)
{
	return my_syscall3(__NR_read, fd, buf, count);
}

/*
 * int reboot(int cmd);
 * <cmd> is among LINUX_REBOOT_CMD_*
 */

static __attribute__((unused))
ssize_t sys_reboot(int magic1, int magic2, int cmd, void *arg)
{
	return my_syscall4(__NR_reboot, magic1, magic2, cmd, arg);
}

/*
 * int getrlimit(int resource, struct rlimit *rlim);
 * int setrlimit(int resource, const struct rlimit *rlim);
 */

static __attribute__((unused))
int sys_prlimit64(pid_t pid, int resource,
		  const struct rlimit64 *new_limit, struct rlimit64 *old_limit)
{
	return my_syscall4(__NR_prlimit64, pid, resource, new_limit, old_limit);
}

/*
 * int sched_yield(void);
 */

static __attribute__((unused))
int sys_sched_yield(void)
{
	return my_syscall0(__NR_sched_yield);
}

/*
 * int select(int nfds, fd_set *read_fds, fd_set *write_fds,
 *            fd_set *except_fds, struct timeval *timeout);
 */

static __attribute__((unused))
int sys_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout)
{
#if defined(__ARCH_WANT_SYS_OLD_SELECT) && !defined(__NR__newselect)
	struct sel_arg_struct {
		unsigned long n;
		fd_set *r, *w, *e;
		struct timeval *t;
	} arg = { .n = nfds, .r = rfds, .w = wfds, .e = efds, .t = timeout };
	return my_syscall1(__NR_select, &arg);
#elif defined(__NR__newselect)
	return my_syscall5(__NR__newselect, nfds, rfds, wfds, efds, timeout);
#elif defined(__NR_select)
	return my_syscall5(__NR_select, nfds, rfds, wfds, efds, timeout);
#elif defined(__NR_pselect6)
	struct timespec t;

	if (timeout) {
		t.tv_sec  = timeout->tv_sec;
		t.tv_nsec = timeout->tv_usec * 1000;
	}
	return my_syscall6(__NR_pselect6, nfds, rfds, wfds, efds, timeout ? &t : NULL, NULL);
#else
	return __nolibc_enosys(__func__, nfds, rfds, wfds, efds, timeout);
#endif
}

static __attribute__((unused))
int msleep(unsigned int msecs)
{
    struct timeval my_timeval = { msecs / 1000, (msecs % 1000) * 1000 };

	if (sys_select(0, 0, 0, 0, &my_timeval) < 0)
		return (my_timeval.tv_sec * 1000) +
				(my_timeval.tv_usec / 1000) +
				!!(my_timeval.tv_usec % 1000);
	else
		return 0;
}

/*
 * int setpgid(pid_t pid, pid_t pgid);
 */

static __attribute__((unused))
int sys_setpgid(pid_t pid, pid_t pgid)
{
	return my_syscall2(__NR_setpgid, pid, pgid);
}

/*
 * pid_t setsid(void);
 */

static __attribute__((unused))
pid_t sys_setsid(void)
{
	return my_syscall0(__NR_setsid);
}

/*
 * int statx(int fd, const char *path, int flags, unsigned int mask, struct statx *buf);
 * int stat(const char *path, struct stat *buf);
 */

static __attribute__((unused))
int sys_statx(int fd, const char *path, int flags, unsigned int mask, struct statx *buf)
{
#ifdef __NR_statx
	return my_syscall5(__NR_statx, fd, path, flags, mask, buf);
#else
	return __nolibc_enosys(__func__, fd, path, flags, mask, buf);
#endif
}

/*
 * int symlink(const char *old, const char *new);
 */

static __attribute__((unused))
int sys_symlink(const char *from, const char *to)
{
#ifdef __NR_symlinkat
	return my_syscall3(__NR_symlinkat, from, AT_FDCWD, to);
#elif defined(__NR_symlink)
	return my_syscall2(__NR_symlink, from, to);
#else
	return __nolibc_enosys(__func__, from, to);
#endif
}

/*
 * mode_t umask(mode_t mode);
 */

static __attribute__((unused))
mode_t sys_umask(mode_t mode)
{
	return my_syscall1(__NR_umask, mode);
}

/*
 * int umount2(const char *path, int flags);
 */

static __attribute__((unused))
int sys_umount2(const char *path, int flags)
{
	return my_syscall2(__NR_umount2, path, flags);
}

/*
 * int unlink(const char *path);
 */

static __attribute__((unused))
int sys_unlink(const char *path)
{
#ifdef __NR_unlinkat
	return my_syscall3(__NR_unlinkat, AT_FDCWD, path, 0);
#elif defined(__NR_unlink)
	return my_syscall1(__NR_unlink, path);
#else
	return __nolibc_enosys(__func__, path);
#endif
}

/*
 * pid_t wait(int *status);
 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
 * pid_t waitpid(pid_t pid, int *status, int options);
 */

static __attribute__((unused))
pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
#ifdef __NR_wait4
	return my_syscall4(__NR_wait4, pid, status, options, rusage);
#else
	return __nolibc_enosys(__func__, pid, status, options, rusage);
#endif
}

/*
 * ssize_t write(int fd, const void *buf, size_t count);
 */

static __attribute__((unused))
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	return my_syscall3(__NR_write, fd, buf, count);
}

/*
 * int memfd_create(const char *name, unsigned int flags);
 */

static __attribute__((unused))
int sys_memfd_create(const char *name, unsigned int flags)
{
	return my_syscall2(__NR_memfd_create, name, flags);
}

#endif /* _NOLIBC_SYS_H */
