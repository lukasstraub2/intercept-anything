
#include "fastpath_preload.h"
#include "sys.h"

#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

static fastpath_entry_t entry = NULL;

static __attribute__((noreturn)) void myabort() {
    sys_kill(sys_getpid(), SIGABRT);
    for (;;)
        ;
}

static void maybe_init() {
    ssize_t ret;

    if (__builtin_expect(!!entry, 0)) {
        return;
    }

    ret = sys_open(PRELOAD_ENTRY_FILE, O_RDONLY, 0);
    if (ret < 0) {
        myabort();
    }
    int fd = ret;

    ret = sys_read(fd, &entry, sizeof(entry));
    sys_close(fd);

    if (ret != sizeof(entry)) {
        myabort();
    }
}

#undef read
__attribute__((visibility("default"))) ssize_t read(int fd,
                                                    void* data,
                                                    size_t len) {
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
__attribute__((visibility("default"))) ssize_t readv(int fd,
                                                     const struct iovec* iov,
                                                     int iovcnt) {
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
__attribute__((visibility("default"))) ssize_t preadv(int fd,
                                                      const struct iovec* iov,
                                                      int iovcnt,
                                                      off_t off) {
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
__attribute__((visibility("default"))) ssize_t
preadv2(int fd, const struct iovec* iov, int iovcnt, off_t off, int flags) {
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
__attribute__((visibility("default"))) ssize_t write(int fd,
                                                     const void* data,
                                                     size_t len) {
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
__attribute__((visibility("default"))) ssize_t writev(int fd,
                                                      const struct iovec* iov,
                                                      int iovcnt) {
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
__attribute__((visibility("default"))) ssize_t pwritev(int fd,
                                                       const struct iovec* iov,
                                                       int iovcnt,
                                                       off_t off) {
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
__attribute__((visibility("default"))) ssize_t
pwritev2(int fd, const struct iovec* iov, int iovcnt, off_t off, int flags) {
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