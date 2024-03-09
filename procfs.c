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

#include "config.h"

#ifdef _FILE_OFFSET_BITS
#undef _FILE_OFFSET_BITS
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>
#include <stdint.h>
#include <limits.h>

#ifdef __linux__
#include <linux/sockios.h>
#endif

/* On some systems SIOCINQ isn't defined, but FIONREAD is just an alias */
#if !defined(SIOCINQ) && defined(FIONREAD)
# define SIOCINQ FIONREAD
#endif

#ifdef O_TMPFILE
# define OPEN_NEEDS_MODE(oflag) \
  (((oflag) & O_CREAT) != 0 || ((oflag) & O_TMPFILE) == O_TMPFILE)
#else
# define OPEN_NEEDS_MODE(oflag) (((oflag) & O_CREAT) != 0)
#endif

/* make sure gcc doesn't redefine open and friends as macros */
#undef open
#undef open64
#undef openat
#undef openat64

static pthread_mutex_t func_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef int (*_ioctl_t)(int, int, void*);
typedef int (*_close_t)(int);
typedef int (*_open_t)(const char *, int, mode_t);
typedef int (*___open_2_t)(const char *, int);
typedef FILE* (*_fopen_t)(const char *path, const char *mode);
#ifdef HAVE_OPENAT
typedef int (*_openat_t)(int, const char *, int, mode_t);
typedef int (*___openat_2_t)(int, const char *, int);
//typedef int (*_openat2_t)(int dirfd, const char *pathname, const struct open_how *how, size_t size);
#endif
typedef int (*_opendir_t)(const char *);
typedef int (*_stat_t)(const char *, struct stat *);
#ifdef _STAT_VER
typedef int (*___xstat_t)(int, const char *, struct stat *);
#endif
#ifdef _GNU_SOURCE
typedef int (*_statx_t)(int dirfd, const char *restrict pathname, int flags,
                        unsigned int mask, struct statx *restrict statxbuf);
#endif
#ifdef HAVE_OPEN64
typedef int (*_open64_t)(const char *, int, mode_t);
typedef int (*___open64_2_t)(const char *, int);
typedef FILE* (*_fopen64_t)(const char *path, const char *mode);
typedef int (*_stat64_t)(const char *, struct stat64 *);
#ifdef _STAT_VER
typedef int (*___xstat64_t)(int, const char *, struct stat64 *);
#endif
#ifdef HAVE_OPENAT
typedef int (*_openat64_t)(int, const char *, int, mode_t);
typedef int (*___openat64_2_t)(int, const char *, int);
#endif
#endif
typedef int (*_fclose_t)(FILE *f);
typedef int (*_access_t)(const char *, int);

static _ioctl_t _ioctl = NULL;
static _close_t _close = NULL;
static _open_t _open = NULL;
static ___open_2_t ___open_2 = NULL;
static _fopen_t _fopen = NULL;
#ifdef HAVE_OPENAT
static _openat_t _openat = NULL;
static ___openat_2_t ___openat_2 = NULL;
//static _openat2_t _openat2 = NULL;
#endif
static _opendir_t _opendir = NULL;
static _stat_t _stat = NULL;
#ifdef _STAT_VER
static ___xstat_t ___xstat = NULL;
#endif
#ifdef _GNU_SOURCE
static _statx_t _statx = NULL;
#endif
#ifdef HAVE_OPEN64
static _open64_t _open64 = NULL;
static ___open64_2_t ___open64_2 = NULL;
static _fopen64_t _fopen64 = NULL;
static _stat64_t _stat64 = NULL;
#ifdef _STAT_VER
static ___xstat64_t ___xstat64 = NULL;
#endif
#ifdef HAVE_OPENAT
static _openat64_t _openat64 = NULL;
static ___openat64_2_t ___openat64_2 = NULL;
#endif
#endif
static _fclose_t _fclose = NULL;
static _access_t _access = NULL;


/* dlsym() violates ISO C, so confide the breakage into this function to
 * avoid warnings. */
typedef void (*fnptr)(void);
static inline fnptr dlsym_fn(void *handle, const char *symbol) {
    return (fnptr) (long) dlsym(handle, symbol);
}

#define LOAD_IOCTL_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_ioctl)  \
        _ioctl = (_ioctl_t) dlsym_fn(RTLD_NEXT, "ioctl"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPEN_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_open) \
        _open = (_open_t) dlsym_fn(RTLD_NEXT, "open"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD___OPEN_2_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___open_2) \
        ___open_2 = (___open_2_t) dlsym_fn(RTLD_NEXT, "__open_2"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPENAT_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_openat) \
        _openat = (_openat_t) dlsym_fn(RTLD_NEXT, "openat"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD___OPENAT_2_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___openat_2) \
        ___openat_2 = (___openat_2_t) dlsym_fn(RTLD_NEXT, "__openat_2"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPEN64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_open64) \
        _open64 = (_open64_t) dlsym_fn(RTLD_NEXT, "open64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD___OPEN64_2_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___open64_2) \
        ___open64_2 = (___open64_2_t) dlsym_fn(RTLD_NEXT, "__open64_2"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPENAT64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_openat64) \
        _openat64 = (_openat64_t) dlsym_fn(RTLD_NEXT, "openat64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD___OPENAT64_2_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___openat64_2) \
        ___openat64_2 = (___openat64_2_t) dlsym_fn(RTLD_NEXT, "__openat64_2"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPENDIR_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_opendir) \
        _opendir = (_opendir_t) dlsym_fn(RTLD_NEXT, "opendir"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_CLOSE_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_close) \
        _close = (_close_t) dlsym_fn(RTLD_NEXT, "close"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_ACCESS_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_access) \
        _access = (_access_t) dlsym_fn(RTLD_NEXT, "access"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_STAT_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_stat) \
        _stat = (_stat_t) dlsym_fn(RTLD_NEXT, "stat"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_STAT64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_stat64) \
        _stat64 = (_stat64_t) dlsym_fn(RTLD_NEXT, "stat64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_XSTAT_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___xstat) \
        ___xstat = (___xstat_t) dlsym_fn(RTLD_NEXT, "__xstat"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_STATX_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_statx) \
        _statx = (_statx_t) dlsym_fn(RTLD_NEXT, "statx"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_XSTAT64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___xstat64) \
        ___xstat64 = (___xstat64_t) dlsym_fn(RTLD_NEXT, "__xstat64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_FOPEN_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_fopen) \
        _fopen = (_fopen_t) dlsym_fn(RTLD_NEXT, "fopen"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_FOPEN64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_fopen64) \
        _fopen64 = (_fopen64_t) dlsym_fn(RTLD_NEXT, "fopen64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_FCLOSE_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_fclose) \
        _fclose = (_fclose_t) dlsym_fn(RTLD_NEXT, "fclose"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

static void debug(int level, const char *format, ...) __attribute__((format (printf, 2, 3)));

#define DEBUG_LEVEL_ALWAYS                0
#define DEBUG_LEVEL_NORMAL                1
#define DEBUG_LEVEL_VERBOSE               2

static void debug(int level, const char *format, ...) {
    va_list ap;
    const char *dlevel_s;
    int dlevel;

    dlevel_s = getenv("PADSP_DEBUG");
    if (!dlevel_s)
        return;

    dlevel = atoi(dlevel_s);

    if (dlevel < level)
        return;

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

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
    LOAD_CLOSE_FUNC();
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

    LOAD_OPEN_FUNC();
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

    LOAD___OPEN_2_FUNC();
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

    LOAD_OPENAT_FUNC();
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

    LOAD___OPENAT_2_FUNC();
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

int opendir(const char *pathname) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": opendir(%s)\n", pathname?pathname:"NULL");

    LOAD_OPENDIR_FUNC();
    if (!pathname) {
        return _opendir(pathname);
    }

    ret = handle_path(pathname);
    if (ret) {
        return ret;
    }

    return _opendir(pathname);
}

#if !defined(__GLIBC__) && !defined(__FreeBSD__)
int ioctl(int fd, int request, ...) {
#else
int ioctl(int fd, unsigned long request, ...) {
#endif
    va_list args;
    void *argp;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": ioctl()\n");

    va_start(args, request);
    argp = va_arg(args, void *);
    va_end(args);

    LOAD_IOCTL_FUNC();
    return _ioctl(fd, request, argp);
}

int close(int fd) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": close()\n");

    LOAD_CLOSE_FUNC();
    return _close(fd);
}

int access(const char *pathname, int mode) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": access(%s)\n", pathname?pathname:"NULL");

    LOAD_ACCESS_FUNC();
    if (!function_enter() || !pathname) {
        return _access(pathname, mode);
    }

    ret = _access(pathname, mode);

    function_exit();

    return ret;
}

int stat(const char *pathname, struct stat *buf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat(%s)\n", pathname?pathname:"NULL");

    LOAD_STAT_FUNC();
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

    LOAD_STAT64_FUNC();
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

    LOAD_OPEN64_FUNC();
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

    LOAD___OPEN64_2_FUNC();
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

    LOAD_OPENAT64_FUNC();
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

    LOAD___OPENAT64_2_FUNC();
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

    LOAD_XSTAT_FUNC();
    if (!pathname) {
        return ___xstat(ver, pathname, buf);
    }

    return ___xstat(ver, pathname, buf);
}

#ifdef HAVE_OPEN64

int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat64(%s)\n", pathname?pathname:"NULL");

    LOAD_XSTAT64_FUNC();
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

    LOAD_STATX_FUNC();
    if (!pathname || pathname[0] != '/') {
        return _statx(dirfd, pathname, flags, mask, statxbuf);
    }

    return _statx(dirfd, pathname, flags, mask, statxbuf);
}

#endif

FILE* fopen(const char *filename, const char *mode) {
    FILE *ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen(%s)\n", filename?filename:"NULL");

    LOAD_FOPEN_FUNC();
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

    LOAD_FOPEN64_FUNC();
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

int fclose(FILE *f) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fclose()\n");

    LOAD_FCLOSE_FUNC();
    return _fclose(f);
}
