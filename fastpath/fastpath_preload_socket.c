#undef _FORTIFY_SOURCE

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "fastpath_preload.h"

#include <errno.h>
#include <syscall.h>
#include <sys/socket.h>

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