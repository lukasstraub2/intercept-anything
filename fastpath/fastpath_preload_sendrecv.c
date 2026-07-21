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
#include <sys/socket.h>
#include <syscall.h>

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