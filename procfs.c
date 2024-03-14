/***
  rootlink. Copied from PluseAudio's padsp.c
  Some code copied from glibc.

  This file is part of PulseAudio.

  Copyright 2006 Lennart Poettering
  Copyright 2006-2007 Pierre Ossman <ossman@cendio.se> for Cendio AB

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published
  by the Free Software Foundation; either version 2.1 of the License,
  or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#define HAVE_OPEN64
#define HAVE_OPENAT
#define _GNU_SOURCE
#define BUF_SIZE (64*1024)

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#define DEBUG_ENV "PROCFS_DEBUG"
#include "config.h"
#include "debug.h"
#include "parent_open.h"
#include "parent_close.h"
#include "parent_stat.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <fcntl.h>

#ifdef O_TMPFILE
# define OPEN_NEEDS_MODE(oflag) \
  (((oflag) & O_CREAT) != 0 || ((oflag) & O_TMPFILE) == O_TMPFILE)
#else
# define OPEN_NEEDS_MODE(oflag) (((oflag) & O_CREAT) != 0)
#endif

static pthread_key_t recursion_key;

static void recursion_key_alloc(void) {
    pthread_key_create(&recursion_key, NULL);
}

static int function_enter(void) {
    /* Avoid recursive calls */
    static pthread_once_t recursion_key_once = PTHREAD_ONCE_INIT;
    pthread_once(&recursion_key_once, recursion_key_alloc);

    if (pthread_getspecific(recursion_key))
        return 0;

    pthread_setspecific(recursion_key, (void*) 1);
    return 1;
}

static void function_exit(void) {
    pthread_setspecific(recursion_key, NULL);
}

static int strcmp_prefix(const char *a, const char *b) {
    return strncmp(a, b, strlen(b));
}

static int handle_uptime() {
    const char *content = "106315.82 92968.73\n";
    size_t content_len = strlen(content);
    char *filename = NULL;
    mode_t _umask;
    int _errno, ret;
    int fd = 0;

    filename = strdup(PREFIX "/tmp/.procfs-XXXXXX");

    _umask = umask(0077);
    ret = mkstemp(filename);
    _errno = errno;
    umask(_umask);

    if (ret < 0) {
        goto fail;
    }
    fd = ret;

    unlink(filename);
    free(filename);
    filename = NULL;

    ret = write(fd, content, content_len);
    if (ret < 0) {
        _errno = errno;
        goto fail;
    } else if (ret != content_len) {
        _errno = EIO;
        goto fail;
    }

    ret = lseek(fd, SEEK_SET, 0);
    if (ret < 0) {
        _errno = errno;
        goto fail;
    }

    return fd;

fail:
    load_close_func();
    _close(fd);
    free(filename);
    errno = _errno;
    return -1;
}

static int handle_path(const char *path) {
    if (!strcmp(path, "/proc/uptime")) {
        return handle_uptime();
    }

    return 0;
}

static FILE error_fptr = {};

static FILE *fhandle_path(const char *path) {
    int ret;

    ret = handle_path(path);
    if (ret < 0) {
        return &error_fptr;
    } else if (ret) {
        return fdopen(ret, "rb");
    } else {
        return 0;
    }
}

int open(const char *filename, int flags, ...) {
    int ret;
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": open(%s)\n", filename?filename:"NULL");

    if (OPEN_NEEDS_MODE(flags)) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = (mode_t) va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    load_open_func();
    if (!filename) {
        return _open(filename, flags, mode);
    }

    ret = handle_path(filename);
    if (ret) {
        return ret;
    }

    return _open(filename, flags, mode);
}

int __open_2(const char *filename, int flags) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open_2(%s)\n", filename?filename:"NULL");

    load___open_2_func();
    if (OPEN_NEEDS_MODE(flags) || !filename) {
        return ___open_2(filename, flags);
    }

    ret = handle_path(filename);
    if (ret) {
        return ret;
    }

    return ___open_2(filename, flags);
}

#ifdef HAVE_OPENAT

int openat(int dirfd, const char *pathname, int flags, ...) {
    int ret;
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": openat(%s)\n", pathname?pathname:"NULL");

    if (OPEN_NEEDS_MODE(flags)) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = (mode_t) va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    load_openat_func();
    if (!pathname || pathname[0] != '/') {
        return _openat(dirfd, pathname, flags, mode);
    }

    ret = handle_path(pathname);
    if (ret) {
        return ret;
    }

    return _openat(dirfd, pathname, flags, mode);
}

int __openat_2(int dirfd, const char *pathname, int flags) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat_2(%s)\n", pathname?pathname:"NULL");

    load___openat_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat_2(dirfd, pathname, flags);
    }

    ret = handle_path(pathname);
    if (ret) {
        return ret;
    }

    return ___openat_2(dirfd, pathname, flags);
}

#endif

int access(const char *pathname, int mode) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": access(%s)\n", pathname?pathname:"NULL");

    load_access_func();
    if (!function_enter() || !pathname) {
        return _access(pathname, mode);
    }

    ret = _access(pathname, mode);

    function_exit();

    return ret;
}

int stat(const char *pathname, struct stat *buf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat(%s)\n", pathname?pathname:"NULL");

    load_stat_func();
    if (!pathname) {
        return _stat(pathname, buf);
    }

    return _stat(pathname, buf);
}
#ifdef HAVE_OPEN64
#undef stat64
#ifdef __GLIBC__
int stat64(const char *pathname, struct stat64 *buf) {
#else
int stat64(const char *pathname, struct stat *buf) {
#endif

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat64(%s)\n", pathname?pathname:"NULL");

    load_stat64_func();
    if (!pathname) {
        return _stat64(pathname, buf);
    }

    return _stat64(pathname, buf);
}
#undef open64
int open64(const char *filename, int flags, ...) {
    int ret;
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": open64(%s)\n", filename?filename:"NULL");

    if (OPEN_NEEDS_MODE(flags)) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    load_open64_func();
    if (!filename) {
        return _open64(filename, flags, mode);
    }

    ret = handle_path(filename);
    if (ret) {
        return ret;
    }

    return _open64(filename, flags, mode);
}

int __open64_2(const char *filename, int flags) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open64_2(%s)\n", filename?filename:"NULL");

    load___open64_2_func();
    if (OPEN_NEEDS_MODE(flags) || !filename) {
        return ___open64_2(filename, flags);
    }

    ret = handle_path(filename);
    if (ret) {
        return ret;
    }

    return ___open64_2(filename, flags);
}

#ifdef HAVE_OPENAT

int openat64(int dirfd, const char *pathname, int flags, ...) {
    int ret;
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": openat64(%s)\n", pathname?pathname:"NULL");

    if (OPEN_NEEDS_MODE(flags)) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = (mode_t) va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    load_openat64_func();
    if (!pathname || pathname[0] != '/') {
        return _openat64(dirfd, pathname, flags, mode);
    }

    ret = handle_path(pathname);
    if (ret) {
        return ret;
    }

    return _openat64(dirfd, pathname, flags, mode);
}

int __openat64_2(int dirfd, const char *pathname, int flags) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat64_2(%s)\n", pathname?pathname:"NULL");

    load___openat64_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat64_2(dirfd, pathname, flags);
    }

    ret = handle_path(pathname);
    if (ret) {
        return ret;
    }

    return ___openat64_2(dirfd, pathname, flags);
}

#endif

#endif

#ifdef _STAT_VER

int __xstat(int ver, const char *pathname, struct stat *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat(%s)\n", pathname?pathname:"NULL");

    load_xstat_func();
    if (!pathname) {
        return ___xstat(ver, pathname, buf);
    }

    return ___xstat(ver, pathname, buf);
}

#ifdef HAVE_OPEN64

int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat64(%s)\n", pathname?pathname:"NULL");

    load_xstat64_func();
    if (!pathname) {
        return ___xstat64(ver, pathname, buf);
    }

    return ___xstat64(ver, pathname, buf);
}

#endif

#endif


#ifdef _GNU_SOURCE

int statx(int dirfd, const char *restrict pathname, int flags,
          unsigned int mask, struct statx *restrict statxbuf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": statx(%s)\n", pathname?pathname:"NULL");

    load_statx_func();
    if (!pathname || pathname[0] != '/') {
        return _statx(dirfd, pathname, flags, mask, statxbuf);
    }

    return _statx(dirfd, pathname, flags, mask, statxbuf);
}

#endif

FILE* fopen(const char *filename, const char *mode) {
    FILE *ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen(%s)\n", filename?filename:"NULL");

    load_fopen_func();
    if (!filename) {
        return _fopen(filename, mode);
    }

    ret = fhandle_path(filename);
    if (ret == &error_fptr) {
        return NULL;
    } else if (ret) {
        return ret;
    }

    return _fopen(filename, mode);
}

#ifdef HAVE_OPEN64
#undef fopen64
FILE *fopen64(const char *__restrict filename, const char *__restrict mode) {
    FILE *ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen64(%s)\n", filename?filename:"NULL");

    load_fopen64_func();
    if (!filename) {
        return _fopen64(filename, mode);
    }

    ret = fhandle_path(filename);
    if (ret == &error_fptr) {
        return NULL;
    } else if (ret) {
        return ret;
    }

    return _fopen64(filename, mode);
}

#endif
