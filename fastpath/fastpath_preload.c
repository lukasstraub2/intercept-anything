#undef _FORTIFY_SOURCE

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "fastpath_preload.h"

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <signal.h>
#include <syscall.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/poll.h>
#include <sys/stat.h>

#ifndef _NSIG
#define _NSIG 65
#endif

#undef read
ssize_t read(int fd, void* data, size_t len) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_read, fd, (unsigned long)data, len, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef pread
ssize_t pread(int fd, void* data, size_t len, off_t off) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_pread64, fd, (unsigned long)data, len, off, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef pread64
ssize_t pread64(int fd, void* data, size_t len, off_t off) {
    return pread(fd, data, len, off);
}

#undef readv
ssize_t readv(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_readv, fd, (unsigned long)iov, iovcnt, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef preadv
ssize_t preadv(int fd, const struct iovec* iov, int iovcnt, off_t off) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_preadv, fd, (unsigned long)iov, iovcnt, (long)(off),
                (long)(off >> 32), 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef preadv2
ssize_t preadv2(int fd,
                const struct iovec* iov,
                int iovcnt,
                off_t off,
                int flags) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_preadv2, fd, (unsigned long)iov, iovcnt, (long)(off),
                (long)(off >> 32), flags);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef write
ssize_t write(int fd, const void* data, size_t len) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_write, fd, (unsigned long)data, len, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef pwrite
ssize_t pwrite(int fd, const void* data, size_t len, off_t off) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_pwrite64, fd, (unsigned long)data, len, off, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef pwrite64
ssize_t pwrite64(int fd, const void* data, size_t len, off_t off) {
    return pwrite(fd, data, len, off);
}

#undef writev
ssize_t writev(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_writev, fd, (unsigned long)iov, iovcnt, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef pwritev
ssize_t pwritev(int fd, const struct iovec* iov, int iovcnt, off_t off) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_pwritev, fd, (unsigned long)iov, iovcnt, (long)(off),
                (long)(off >> 32), 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef pwritev2
ssize_t pwritev2(int fd,
                 const struct iovec* iov,
                 int iovcnt,
                 off_t off,
                 int flags) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_pwritev2, fd, (unsigned long)iov, iovcnt, (long)(off),
                (long)(off >> 32), flags);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef sendto
ssize_t sendto(int fd,
               const void* buf,
               size_t len,
               int flags,
               const struct sockaddr* addr,
               socklen_t addr_len) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_sendto, fd, (unsigned long)buf, len, flags,
                (unsigned long)addr, addr_len);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef send
ssize_t send(int fd, const void* buf, size_t len, int flags) {
    return sendto(fd, buf, len, flags, NULL, 0);
}

#undef sendmsg
ssize_t sendmsg(int fd, const struct msghdr* msg, int flags) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_sendmsg, fd, (unsigned long)msg, flags, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef sendmmsg
int sendmmsg(int fd, struct mmsghdr* msgvec, unsigned int vlen, int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_sendmmsg, fd, (unsigned long)msgvec, vlen, flags, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef recvfrom
ssize_t recvfrom(int fd,
                 void* buf,
                 size_t len,
                 int flags,
                 struct sockaddr* addr,
                 socklen_t* addr_len) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_recvfrom, fd, (unsigned long)buf, len, flags,
                (unsigned long)addr, (unsigned long)addr_len);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef recv
ssize_t recv(int fd, void* buf, size_t len, int flags) {
    return recvfrom(fd, buf, len, flags, NULL, NULL);
}

#undef recvmsg
ssize_t recvmsg(int fd, struct msghdr* msg, int flags) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_recvmsg, fd, (unsigned long)msg, flags, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef recvmmsg
int recvmmsg(int fd,
             struct mmsghdr* msgvec,
             unsigned int vlen,
             int flags,
             struct timespec* timeout) {
    int ret;

    maybe_init();

    ret = entry(__NR_recvmmsg, fd, (unsigned long)msgvec, vlen, flags,
                (unsigned long)timeout, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef msync
int msync(void* addr, size_t len, int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_msync, (unsigned long)addr, len, flags, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

int kill(pid_t pid, int sig) {
    int ret;

    maybe_init();

    ret = entry(__NR_kill, pid, sig, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef sendfile
ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
    ssize_t ret;

    maybe_init();

    ret =
        entry(__NR_sendfile, out_fd, in_fd, (unsigned long)offset, count, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef sendfile64
ssize_t sendfile64(int out_fd, int in_fd, off_t* offset, size_t count) {
    return sendfile(out_fd, in_fd, offset, count);
}

ssize_t splice(int in_fd,
               off_t* in_off,
               int out_fd,
               off_t* out_off,
               size_t len,
               unsigned int flags) {
    ssize_t ret;

    maybe_init();

    ret = entry(__NR_splice, in_fd, (unsigned long)in_off, out_fd,
                (unsigned long)out_off, len, flags);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_wait
int epoll_wait(int epfd,
               struct epoll_event* events,
               int maxevents,
               int timeout) {
#ifdef __NR_epoll_wait
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_wait, epfd, (unsigned long)events, maxevents,
                timeout, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
#else
    return epoll_pwait(epfd, events, maxevents, timeout, NULL);
#endif
}

#undef epoll_pwait
int epoll_pwait(int epfd,
                struct epoll_event* events,
                int maxevents,
                int timeout,
                const sigset_t* sigmask) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_pwait, epfd, (unsigned long)events, maxevents,
                timeout, (unsigned long)sigmask, _NSIG / 8);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_pwait2
int epoll_pwait2(int epfd,
                 struct epoll_event* events,
                 int maxevents,
                 const struct timespec* timeout,
                 const sigset_t* sigmask) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_pwait2, epfd, (unsigned long)events, maxevents,
                (unsigned long)timeout, (unsigned long)sigmask, _NSIG / 8);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_create
int epoll_create(int size) {
#ifdef __NR_epoll_create
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_create, size, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
#else
    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }

    return epoll_create1(0);
#endif
}

#undef epoll_create1
int epoll_create1(int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_create1, flags, 0, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef epoll_ctl
int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) {
    int ret;

    maybe_init();

    ret = entry(__NR_epoll_ctl, epfd, op, fd, (unsigned long)event, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef poll
int poll(struct pollfd* fds, nfds_t nfds, int timeout) {
#ifdef __NR_poll
    int ret;

    maybe_init();

    ret = entry(__NR_poll, (unsigned long)fds, nfds, timeout, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
#else
    struct timespec timeout_ts;
    struct timespec* timeout_ts_p = NULL;

    if (timeout >= 0) {
        timeout_ts.tv_sec = timeout / 1000;
        timeout_ts.tv_nsec = (timeout % 1000) * 1000000;
        timeout_ts_p = &timeout_ts;
    }

    return ppoll(fds, nfds, timeout_ts_p, NULL);
#endif
}

#undef ppoll
int ppoll(struct pollfd* fds,
          nfds_t nfds,
          const struct timespec* tmo_p,
          const sigset_t* sigmask) {
    int ret;

    maybe_init();

    ret = entry(__NR_ppoll, (unsigned long)fds, nfds, (unsigned long)tmo_p,
                (unsigned long)sigmask, _NSIG / 8, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef accept
int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
    int ret;

    maybe_init();

    ret = entry(__NR_accept, sockfd, (unsigned long)addr,
                (unsigned long)addrlen, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef accept4
int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) {
    int ret;

    maybe_init();

    ret = entry(__NR_accept4, sockfd, (unsigned long)addr,
                (unsigned long)addrlen, flags, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef open
int open(const char* pathname, int flags, ...) {
    int ret;
    mode_t mode = 0;

#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    maybe_init();

    ret = entry(__NR_openat, AT_FDCWD, (unsigned long)pathname, flags, mode, 0,
                0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef creat
int creat(const char* pathname, mode_t mode) {
    return open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

#undef openat
int openat(int dirfd, const char* pathname, int flags, ...) {
    int ret;
    mode_t mode = 0;

#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    maybe_init();

    ret = entry(__NR_openat, dirfd, (unsigned long)pathname, flags, mode, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef openat2
int openat2(int dirfd,
            const char* pathname,
            const struct open_how* how,
            size_t size) {
    int ret;

    maybe_init();

    ret = entry(__NR_openat2, dirfd, (unsigned long)pathname,
                (unsigned long)how, size, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef __open_2
int __open_2(const char* pathname, int flags) {
    /* Fortify wrappers intentionally omit the mode parameter. Forwarding to
     * open handles this gracefully. */
    return open(pathname, flags, 0);
}

#undef open64
int open64(const char* pathname, int flags, ...) {
    mode_t mode = 0;

#ifdef O_TMPFILE
    if (flags & (O_CREAT | O_TMPFILE)) {
#else
    if (flags & O_CREAT) {
#endif
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    return open(pathname, flags, mode);
}

#undef __open64_2
int __open64_2(const char* pathname, int flags) {
    return open(pathname, flags, 0);
}

#undef shutdown
int shutdown(int sockfd, int how) {
    int ret;

    maybe_init();

    ret = entry(__NR_shutdown, sockfd, how, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef getsockopt
int getsockopt(int sockfd,
               int level,
               int optname,
               void* optval,
               socklen_t* optlen) {
    int ret;

    maybe_init();

    ret = entry(__NR_getsockopt, sockfd, level, optname, (unsigned long)optval,
                (unsigned long)optlen, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef setsockopt
int setsockopt(int sockfd,
               int level,
               int optname,
               const void* optval,
               socklen_t optlen) {
    int ret;

    maybe_init();

    ret = entry(__NR_setsockopt, sockfd, level, optname, (unsigned long)optval,
                optlen, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef stat
int stat(const char* pathname, struct stat* statbuf) {
    return fstatat(AT_FDCWD, pathname, statbuf, 0);
}

#undef fstat
int fstat(int fd, struct stat* statbuf) {
    int ret;

    maybe_init();

    ret = entry(__NR_fstat, fd, (unsigned long)statbuf, 0, 0, 0, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef lstat
int lstat(const char* pathname, struct stat* statbuf) {
    return fstatat(AT_FDCWD, pathname, statbuf, AT_SYMLINK_NOFOLLOW);
}

#undef fstatat
int fstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    int ret;

    maybe_init();

#if defined(__NR_newfstatat)
    ret = entry(__NR_newfstatat, dirfd, (unsigned long)pathname,
                (unsigned long)statbuf, flags, 0, 0);
#else
    ret = entry(__NR_fstatat64, dirfd, (unsigned long)pathname,
                (unsigned long)statbuf, flags, 0, 0);
#endif

    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}

#undef stat64
int stat64(const char* pathname, struct stat64* statbuf) {
    return stat64(pathname, statbuf);
}

#undef __xstat
int __xstat(int ver, const char* pathname, struct stat* buf) {
    /* glibc internals historically utilize the 'ver' parameter for ABI
       matching, but standard kernel wrappers intercepting the syscall can
       simply forward to stat */
    return stat(pathname, buf);
}

#undef __xstat64
int __xstat64(int ver, const char* pathname, struct stat64* buf) {
    return stat64(pathname, buf);
}

#undef statx
int statx(int dirfd,
          const char* pathname,
          int flags,
          unsigned int mask,
          struct statx* statxbuf) {
    int ret;

    maybe_init();

    ret = entry(__NR_statx, dirfd, (unsigned long)pathname, flags, mask,
                (unsigned long)statxbuf, 0);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    return ret;
}