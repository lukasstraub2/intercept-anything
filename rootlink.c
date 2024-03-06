/***
  rootlink. Copied from PluseAudio's padsp.c

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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

#ifdef __linux__
#include <linux/sockios.h>
#endif

/* On some systems SIOCINQ isn't defined, but FIONREAD is just an alias */
#if !defined(SIOCINQ) && defined(FIONREAD)
# define SIOCINQ FIONREAD
#endif

/* make sure gcc doesn't redefine open and friends as macros */
#undef open
#undef open64

static pthread_mutex_t fd_infos_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t func_mutex = PTHREAD_MUTEX_INITIALIZER;

static int (*_ioctl)(int, int, void*) = NULL;
static int (*_close)(int) = NULL;
static int (*_open)(const char *, int, mode_t) = NULL;
static int (*___open_2)(const char *, int) = NULL;
static FILE* (*_fopen)(const char *path, const char *mode) = NULL;
static int (*_stat)(const char *, struct stat *) = NULL;
#ifdef _STAT_VER
static int (*___xstat)(int, const char *, struct stat *) = NULL;
#endif
#ifdef HAVE_OPEN64
static int (*_open64)(const char *, int, mode_t) = NULL;
static int (*___open64_2)(const char *, int) = NULL;
static FILE* (*_fopen64)(const char *path, const char *mode) = NULL;
static int (*_stat64)(const char *, struct stat64 *) = NULL;
#ifdef _STAT_VER
static int (*___xstat64)(int, const char *, struct stat64 *) = NULL;
#endif
#endif
static int (*_fclose)(FILE *f) = NULL;
static int (*_access)(const char *, int) = NULL;

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
        _ioctl = (int (*)(int, int, void*)) dlsym_fn(RTLD_NEXT, "ioctl"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPEN_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_open) \
        _open = (int (*)(const char *, int, mode_t)) dlsym_fn(RTLD_NEXT, "open"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD___OPEN_2_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___open_2) \
        ___open_2 = (int (*)(const char *, int)) dlsym_fn(RTLD_NEXT, "__open_2"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_OPEN64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_open64) \
        _open64 = (int (*)(const char *, int, mode_t)) dlsym_fn(RTLD_NEXT, "open64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD___OPEN64_2_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___open64_2) \
        ___open64_2 = (int (*)(const char *, int)) dlsym_fn(RTLD_NEXT, "__open64_2"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_CLOSE_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_close) \
        _close = (int (*)(int)) dlsym_fn(RTLD_NEXT, "close"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_ACCESS_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_access) \
        _access = (int (*)(const char*, int)) dlsym_fn(RTLD_NEXT, "access"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_STAT_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_stat) \
        _stat = (int (*)(const char *, struct stat *)) dlsym_fn(RTLD_NEXT, "stat"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_STAT64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_stat64) \
        _stat64 = (int (*)(const char *, struct stat64 *)) dlsym_fn(RTLD_NEXT, "stat64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_XSTAT_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___xstat) \
        ___xstat = (int (*)(int, const char *, struct stat *)) dlsym_fn(RTLD_NEXT, "__xstat"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_XSTAT64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!___xstat64) \
        ___xstat64 = (int (*)(int, const char *, struct stat64 *)) dlsym_fn(RTLD_NEXT, "__xstat64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_FOPEN_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_fopen) \
        _fopen = (FILE* (*)(const char *, const char*)) dlsym_fn(RTLD_NEXT, "fopen"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_FOPEN64_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_fopen64) \
        _fopen64 = (FILE* (*)(const char *, const char*)) dlsym_fn(RTLD_NEXT, "fopen64"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_FCLOSE_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_fclose) \
        _fclose = (int (*)(FILE *)) dlsym_fn(RTLD_NEXT, "fclose"); \
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

static void atfork_prepare(void) {

    debug(DEBUG_LEVEL_NORMAL, __FILE__": atfork_prepare() enter\n");

    function_enter();

    // Take all locks

    debug(DEBUG_LEVEL_NORMAL, __FILE__": atfork_prepare() exit\n");
}

static void atfork_parent(void) {

    debug(DEBUG_LEVEL_NORMAL, __FILE__": atfork_parent() enter\n");

    // Drop all locks and continue

    function_exit();

    debug(DEBUG_LEVEL_NORMAL, __FILE__": atfork_parent() exit\n");
}

static void atfork_child(void) {

    debug(DEBUG_LEVEL_NORMAL, __FILE__": atfork_child() enter\n");

    // Unlock/override mutexes, free everything

    function_exit();

    debug(DEBUG_LEVEL_NORMAL, __FILE__": atfork_child() exit\n");
}

static void install_atfork(void) {
    pthread_atfork(atfork_prepare, atfork_parent, atfork_child);
}

static int real_open(const char *filename, int flags, mode_t mode) {
    int r, _errno = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": open(%s)\n", filename?filename:"NULL");

    if (!function_enter()) {
        LOAD_OPEN_FUNC();
        return _open(filename, flags, mode);
    }

    if (/*Not handled by us?*/ 1) {
        function_exit();
        LOAD_OPEN_FUNC();
        return _open(filename, flags, mode);
    }

    function_exit();

    if (_errno)
        errno = _errno;

    return r;
}

int open(const char *filename, int flags, ...) {
    va_list args;
    mode_t mode = 0;

    if (flags & O_CREAT) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = (mode_t) va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    return real_open(filename, flags, mode);
}

int __open_2(const char *filename, int flags) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open_2(%s)\n", filename?filename:"NULL");

    if ((flags & O_CREAT) ||
        !filename ||
        /*Not handled by us?*/ 1) {
        LOAD___OPEN_2_FUNC();
        return ___open_2(filename, flags);
    }
    return real_open(filename, flags, 0);
}

#if !defined(__GLIBC__) && !defined(__FreeBSD__)
int ioctl(int fd, int request, ...) {
#else
int ioctl(int fd, unsigned long request, ...) {
#endif
    va_list args;
    void *argp;
    int r, _errno = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": ioctl()\n");

    va_start(args, request);
    argp = va_arg(args, void *);
    va_end(args);

    if (!function_enter()) {
        LOAD_IOCTL_FUNC();
        return _ioctl(fd, request, argp);
    }

    if (/*Not our fd?*/ 1) {
        function_exit();
        LOAD_IOCTL_FUNC();
        return _ioctl(fd, request, argp);
    }

    if (_errno)
        errno = _errno;

    function_exit();

    return r;
}

int close(int fd) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": close()\n");

    if (!function_enter()) {
        LOAD_CLOSE_FUNC();
        return _close(fd);
    }

    if (/*Not our fd?*/ 1) {
        function_exit();
        LOAD_CLOSE_FUNC();
        return _close(fd);
    }

    function_exit();

    return 0;
}

int access(const char *pathname, int mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": access(%s)\n", pathname?pathname:"NULL");

    if (!pathname ||
        /*Not handled by us?*/ 1) {
        LOAD_ACCESS_FUNC();
        return _access(pathname, mode);
    }

    if (mode & X_OK) {
        debug(DEBUG_LEVEL_NORMAL, __FILE__": access(%s, %x) = EACCESS\n", pathname, mode);
        errno = EACCES;
        return -1;
    }

    debug(DEBUG_LEVEL_NORMAL, __FILE__": access(%s, %x) = OK\n", pathname, mode);

    return 0;
}

int stat(const char *pathname, struct stat *buf) {
#ifdef HAVE_OPEN64
    struct stat64 parent;
#else
    struct stat parent;
#endif
    int ret;

    if (!pathname ||
        !buf ||
        /*Not handled by us?*/ 1) {
        debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat(%s)\n", pathname?pathname:"NULL");
        LOAD_STAT_FUNC();
        return _stat(pathname, buf);
    }

    debug(DEBUG_LEVEL_NORMAL, __FILE__": stat(%s)\n", pathname);

#ifdef _STAT_VER
#ifdef HAVE_OPEN64
    ret = __xstat64(_STAT_VER, "/dev", &parent);
#else
    ret = __xstat(_STAT_VER, "/dev", &parent);
#endif
#else
#ifdef HAVE_OPEN64
    ret = stat64("/dev", &parent);
#else
    ret = stat("/dev", &parent);
#endif
#endif

    if (ret) {
        debug(DEBUG_LEVEL_NORMAL, __FILE__": unable to stat \"/dev\"\n");
        return -1;
    }

    buf->st_dev = parent.st_dev;
    buf->st_ino = 0xDEADBEEF;   /* FIXME: Can we do this in a safe way? */
    buf->st_mode = S_IFCHR | S_IRUSR | S_IWUSR;
    buf->st_nlink = 1;
    buf->st_uid = getuid();
    buf->st_gid = getgid();
    buf->st_rdev = 0x0E03;      /* FIXME: Linux specific */
    buf->st_size = 0;
    buf->st_atime = 1181557705;
    buf->st_mtime = 1181557705;
    buf->st_ctime = 1181557705;
    buf->st_blksize = 1;
    buf->st_blocks = 0;

    return 0;
}
#ifdef HAVE_OPEN64
#undef stat64
#ifdef __GLIBC__
int stat64(const char *pathname, struct stat64 *buf) {
#else
int stat64(const char *pathname, struct stat *buf) {
#endif
    struct stat oldbuf;
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat64(%s)\n", pathname?pathname:"NULL");

    if (!pathname ||
        !buf ||
        !is_audio_device_node(pathname)) {
        LOAD_STAT64_FUNC();
        return _stat64(pathname, buf);
    }

    ret = stat(pathname, &oldbuf);
    if (ret)
        return ret;

    buf->st_dev = oldbuf.st_dev;
    buf->st_ino = oldbuf.st_ino;
    buf->st_mode = oldbuf.st_mode;
    buf->st_nlink = oldbuf.st_nlink;
    buf->st_uid = oldbuf.st_uid;
    buf->st_gid = oldbuf.st_gid;
    buf->st_rdev = oldbuf.st_rdev;
    buf->st_size = oldbuf.st_size;
    buf->st_atime = oldbuf.st_atime;
    buf->st_mtime = oldbuf.st_mtime;
    buf->st_ctime = oldbuf.st_ctime;
    buf->st_blksize = oldbuf.st_blksize;
    buf->st_blocks = oldbuf.st_blocks;

    return 0;
}
#undef open64
int open64(const char *filename, int flags, ...) {
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": open64(%s)\n", filename?filename:"NULL");

    if (flags & O_CREAT) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (!filename ||
        !is_audio_device_node(filename)) {
        LOAD_OPEN64_FUNC();
        return _open64(filename, flags, mode);
    }

    return real_open(filename, flags, mode);
}

int __open64_2(const char *filename, int flags) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open64_2(%s)\n", filename?filename:"NULL");

    if ((flags & O_CREAT) ||
        !filename ||
        !is_audio_device_node(filename)) {
        LOAD___OPEN64_2_FUNC();
        return ___open64_2(filename, flags);
    }

    return real_open(filename, flags, 0);
}

#endif

#ifdef _STAT_VER

int __xstat(int ver, const char *pathname, struct stat *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat(%s)\n", pathname?pathname:"NULL");

    if (!pathname ||
        !buf ||
        !is_audio_device_node(pathname)) {
        LOAD_XSTAT_FUNC();
        return ___xstat(ver, pathname, buf);
    }

    if (ver != _STAT_VER) {
        errno = EINVAL;
        return -1;
    }

    return stat(pathname, buf);
}

#ifdef HAVE_OPEN64

int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat64(%s)\n", pathname?pathname:"NULL");

    if (!pathname ||
        !buf ||
        !is_audio_device_node(pathname)) {
        LOAD_XSTAT64_FUNC();
        return ___xstat64(ver, pathname, buf);
    }

    if (ver != _STAT_VER) {
        errno = EINVAL;
        return -1;
    }

    return stat64(pathname, buf);
}

#endif

#endif

FILE* fopen(const char *filename, const char *mode) {
    FILE *f = NULL;
    int fd;
    mode_t m;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen(%s)\n", filename?filename:"NULL");

    if (!filename ||
        !mode ||
        /*Not handled by us?*/ 1) {
        LOAD_FOPEN_FUNC();
        return _fopen(filename, mode);
    }

    switch (mode[0]) {
    case 'r':
        m = O_RDONLY;
        break;
    case 'w':
    case 'a':
        m = O_WRONLY;
        break;
    default:
        errno = EINVAL;
        return NULL;
    }

    if ((((mode[1] == 'b') || (mode[1] == 't')) && (mode[2] == '+')) || (mode[1] == '+'))
        m = O_RDWR;

    if ((fd = real_open(filename, m, 0)) < 0)
        return NULL;

    if (!(f = fdopen(fd, mode))) {
        close(fd);
        return NULL;
    }

    return f;
}

#ifdef HAVE_OPEN64
#undef fopen64
FILE *fopen64(const char *__restrict filename, const char *__restrict mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen64(%s)\n", filename?filename:"NULL");

    if (!filename ||
        !mode ||
        /*Not handled by us?*/ 1) {
        LOAD_FOPEN64_FUNC();
        return _fopen64(filename, mode);
    }

    return fopen(filename, mode);
}

#endif

int fclose(FILE *f) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fclose()\n");

    if (!function_enter()) {
        LOAD_FCLOSE_FUNC();
        return _fclose(f);
    }

    if (/*Not our fd?*/ 1) {
        function_exit();
        LOAD_FCLOSE_FUNC();
        return _fclose(f);
    }

    function_exit();

    LOAD_FCLOSE_FUNC();
    return _fclose(f);
}
