#undef _FORTIFY_SOURCE

#include "fastpath_preload.h"

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <signal.h>
#include <syscall.h>

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
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
