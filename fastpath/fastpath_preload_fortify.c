#define _FORTIFY_SOURCE 3

#include "fastpath_preload.h"
#include <unistd.h>
#include <sys/socket.h>

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

// weak dynamic symbol, may be NULL if not provided by runtime
extern void __chk_fail() __attribute__((weak));

static void do_chk_fail() {
    if (__chk_fail) {
        __chk_fail();
    } else {
        myabort();
    }
}

#undef __read_chk
ssize_t __read_chk(int fd, void* data, size_t len, size_t buflen) {
    if (len > buflen) {
        do_chk_fail();
    }

    return read(fd, data, len);
}

#undef __pread_chk
ssize_t __pread_chk(int fd, void* data, size_t len, off_t off, size_t buflen) {
    if (len > buflen) {
        do_chk_fail();
    }

    return pread(fd, data, len, off);
}

#undef __pread64_chk
ssize_t __pread64_chk(int fd,
                      void* data,
                      size_t len,
                      off_t off,
                      size_t buflen) {
    if (len > buflen) {
        do_chk_fail();
    }

    return pread64(fd, data, len, off);
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