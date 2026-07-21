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
#include <unistd.h>
#include <sys/uio.h>
#include <sys/sendfile.h>

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

#undef preadv64v2
ssize_t preadv64v2(int fd,
                   const struct iovec* iov,
                   int iovcnt,
                   off_t off,
                   int flags) {
    return preadv2(fd, iov, iovcnt, off, flags);
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

#undef pwritev64v2
ssize_t pwritev64v2(int fd,
                    const struct iovec* iov,
                    int iovcnt,
                    off_t off,
                    int flags) {
    return pwritev2(fd, iov, iovcnt, off, flags);
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