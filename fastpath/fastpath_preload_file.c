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
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>

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
    return stat(pathname, statbuf);
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