#define _FORTIFY_SOURCE 3

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include "fastpath_preload.h"

#include <unistd.h>
#include <sys/socket.h>

// weak dynamic symbol, may be NULL if not provided by runtime
extern void __chk_fail() __attribute__((weak));

static void do_chk_fail() {
    if (__chk_fail) {
        __chk_fail();
    } else {
        myabort();
    }
}

#undef __recv_chk
ssize_t __recv_chk(int fd, void* buf, size_t len, size_t buflen, int flags) {
    if (len > buflen) {
        do_chk_fail();
    }

    return recv(fd, buf, len, flags);
}

#undef __recvfrom_chk
ssize_t __recvfrom_chk(int fd,
                       void* buf,
                       size_t len,
                       size_t buflen,
                       int flags,
                       struct sockaddr* addr,
                       socklen_t* addr_len) {
    if (len > buflen) {
        do_chk_fail();
    }

    return recvfrom(fd, buf, len, flags, addr, addr_len);
}