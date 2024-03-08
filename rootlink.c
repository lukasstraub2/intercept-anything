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

typedef int (*_execve_t)(const char *pathname, char *const argv[], char *const envp[]);
typedef int (*_execveat_t)(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
typedef int (*_execl_t)(const char *pathname, const char *arg, ... /*, (char *) NULL */);
typedef int (*_execlp_t)(const char *file, const char *arg, ... /*, (char *) NULL */);
typedef int (*_execle_t)(const char *pathname, const char *arg, ... /*, (char *) NULL, char *const envp[] */);
typedef int (*_execv_t)(const char *pathname, char *const argv[]);
typedef int (*_execvp_t)(const char *file, char *const argv[]);
#ifdef _GNU_SOURCE
typedef int (*_execvpe_t)(const char *file, char *const argv[], char *const envp[]);
#endif
typedef int (*_posix_spawn_t)(pid_t *restrict pid, const char *restrict path,
                       const posix_spawn_file_actions_t *restrict file_actions,
                       const posix_spawnattr_t *restrict attrp,
                       char *const argv[restrict],
                       char *const envp[restrict]);
typedef int (*_posix_spawnp_t)(pid_t *restrict pid, const char *restrict file,
                       const posix_spawn_file_actions_t *restrict file_actions,
                       const posix_spawnattr_t *restrict attrp,
                       char *const argv[restrict],
                       char *const envp[restrict]);


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

static _execve_t _execve = NULL;
static _execveat_t _execveat = NULL;
//static _execl_t _execl = NULL;
//static _execlp_t _execlp = NULL;
//static _execle_t _execle = NULL;
//static _execv_t _execv = NULL;
//static _execvp_t _execvp = NULL;
//#ifdef _GNU_SOURCE
//static _execvpe_t _execvpe = NULL;
//#endif
static _posix_spawn_t _posix_spawn = NULL;
static _posix_spawnp_t _posix_spawnp = NULL;


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

#define LOAD_EXECVE_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_execve) \
        _execve = (_execve_t) dlsym_fn(RTLD_NEXT, "execve"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_EXECVEAT_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_execveat) \
        _execveat = (_execveat_t) dlsym_fn(RTLD_NEXT, "execveat"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

//#define LOAD_EXECL_FUNC() \
//do { \
    //pthread_mutex_lock(&func_mutex); \
    //if (!_execl) \
        //_execl = (_execl_t) dlsym_fn(RTLD_NEXT, "execl"); \
    //pthread_mutex_unlock(&func_mutex); \
//} while(0)

//#define LOAD_EXECLP_FUNC() \
//do { \
    //pthread_mutex_lock(&func_mutex); \
    //if (!_execlp) \
        //_execlp = (_execlp_t) dlsym_fn(RTLD_NEXT, "execlp"); \
    //pthread_mutex_unlock(&func_mutex); \
//} while(0)

//#define LOAD_EXECLE_FUNC() \
//do { \
    //pthread_mutex_lock(&func_mutex); \
    //if (!_execle) \
        //_execle = (_execle_t) dlsym_fn(RTLD_NEXT, "execle"); \
    //pthread_mutex_unlock(&func_mutex); \
//} while(0)

//#define LOAD_EXECV_FUNC() \
//do { \
    //pthread_mutex_lock(&func_mutex); \
    //if (!_execv) \
        //_execv = (_execv_t) dlsym_fn(RTLD_NEXT, "execv"); \
    //pthread_mutex_unlock(&func_mutex); \
//} while(0)

//#define LOAD_EXECVP_FUNC() \
//do { \
    //pthread_mutex_lock(&func_mutex); \
    //if (!_execvp) \
        //_execvp = (_execvp_t) dlsym_fn(RTLD_NEXT, "execvp"); \
    //pthread_mutex_unlock(&func_mutex); \
//} while(0)

//#define LOAD_EXECVPE_FUNC() \
//do { \
    //pthread_mutex_lock(&func_mutex); \
    //if (!_execvpe) \
        //_execvpe = (_execvpe_t) dlsym_fn(RTLD_NEXT, "execvpe"); \
    //pthread_mutex_unlock(&func_mutex); \
//} while(0)

#define LOAD_POSIX_SPAWN_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_posix_spawn) \
        _posix_spawn = (_posix_spawn_t) dlsym_fn(RTLD_NEXT, "posix_spawn"); \
    pthread_mutex_unlock(&func_mutex); \
} while(0)

#define LOAD_POSIX_SPAWNP_FUNC() \
do { \
    pthread_mutex_lock(&func_mutex); \
    if (!_posix_spawnp) \
        _posix_spawnp = (_posix_spawnp_t) dlsym_fn(RTLD_NEXT, "posix_spawnp"); \
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

static void __attribute__((constructor)) initialize() {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": disabling SIGSYS\n");

    signal(SIGSYS, SIG_IGN);
}

static int handle_path(const char *path) {
    return strcmp(path, "/bin") == 0 || strcmp(path, "/usr") == 0 ||
            strncmp(path, "/bin/", 5) == 0 || strncmp(path, "/usr/", 5) == 0;
}

static void _mangle_path(char *out, const char *path) {
    const char *prefix = "/data/data/com.termux/files/home/gentoo";
    int prefix_len = strlen(prefix);
    int path_len = strlen(path);

    out[0] = '\0';
    if (!handle_path(path) || prefix_len + path_len + 1 > BUF_SIZE) {
        strncpy(out, path, BUF_SIZE);
        out[BUF_SIZE -1] = '\0';
        return;
    }

    strcpy(out, prefix);
    strncpy(out + prefix_len, path, BUF_SIZE - prefix_len);
    out[BUF_SIZE -1] = '\0';
}

#define MANGLE_PATH(__path) \
    char path_buf[PATH_MAX]; \
    _mangle_path(path_buf, (__path)); \
    (__path) = path_buf;

int open(const char *filename, int flags, ...) {
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

    MANGLE_PATH(filename);
    return _open(filename, flags, mode);
}

int __open_2(const char *filename, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open_2(%s)\n", filename?filename:"NULL");

    LOAD___OPEN_2_FUNC();
    if (OPEN_NEEDS_MODE(flags) || !filename) {
        return ___open_2(filename, flags);
    }

    MANGLE_PATH(filename);
    return ___open_2(filename, flags);
}

#ifdef HAVE_OPENAT

int openat(int dirfd, const char *pathname, int flags, ...) {
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

    MANGLE_PATH(pathname);
    return _openat(dirfd, pathname, flags, mode);
}

int __openat_2(int dirfd, const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat_2(%s)\n", pathname?pathname:"NULL");

    LOAD___OPENAT_2_FUNC();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat_2(dirfd, pathname, flags);
    }

    MANGLE_PATH(pathname);
    return ___openat_2(dirfd, pathname, flags);
}

#endif

int opendir(const char *pathname) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": opendir(%s)\n", pathname?pathname:"NULL");

    LOAD_OPENDIR_FUNC();
    if (!pathname) {
        return _opendir(pathname);
    }

    MANGLE_PATH(pathname);
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

    MANGLE_PATH(pathname);
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

    MANGLE_PATH(pathname);
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

    MANGLE_PATH(pathname);
    return _stat64(pathname, buf);
}
#undef open64
int open64(const char *filename, int flags, ...) {
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

    MANGLE_PATH(filename);
    return _open64(filename, flags, mode);
}

int __open64_2(const char *filename, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open64_2(%s)\n", filename?filename:"NULL");

    LOAD___OPEN64_2_FUNC();
    if (OPEN_NEEDS_MODE(flags) || !filename) {
        return ___open64_2(filename, flags);
    }

    MANGLE_PATH(filename);
    return ___open64_2(filename, flags);
}

#ifdef HAVE_OPENAT

int openat64(int dirfd, const char *pathname, int flags, ...) {
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

    MANGLE_PATH(pathname);
    return _openat64(dirfd, pathname, flags, mode);
}

int __openat64_2(int dirfd, const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat64_2(%s)\n", pathname?pathname:"NULL");

    LOAD___OPENAT64_2_FUNC();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat64_2(dirfd, pathname, flags);
    }

    MANGLE_PATH(pathname);
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

    MANGLE_PATH(pathname);
    return ___xstat(ver, pathname, buf);
}

#ifdef HAVE_OPEN64

int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat64(%s)\n", pathname?pathname:"NULL");

    LOAD_XSTAT64_FUNC();
    if (!pathname) {
        return ___xstat64(ver, pathname, buf);
    }

    MANGLE_PATH(pathname);
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

    MANGLE_PATH(pathname);
    return _statx(dirfd, pathname, flags, mask, statxbuf);
}

#endif

FILE* fopen(const char *filename, const char *mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen(%s)\n", filename?filename:"NULL");

    LOAD_FOPEN_FUNC();
    if (!filename) {
        return _fopen(filename, mode);
    }

    MANGLE_PATH(filename);
    return _fopen(filename, mode);
}

#ifdef HAVE_OPEN64
#undef fopen64
FILE *fopen64(const char *__restrict filename, const char *__restrict mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen64(%s)\n", filename?filename:"NULL");

    LOAD_FOPEN64_FUNC();
    if (!filename) {
        return _fopen64(filename, mode);
    }

    MANGLE_PATH(filename);
    return _fopen64(filename, mode);
}

#endif

int fclose(FILE *f) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fclose()\n");

    LOAD_FCLOSE_FUNC();
    return _fclose(f);
}

static int64_t array_len(char *const array[]) {
    int64_t len;

    for (len = 0; array[len]; len++) {
        if (len == INT_MAX) {
            return -1;
        }
    }

    return len;
}

static void array_copy(char *const source[], char *dest[], int64_t len) {
    memcpy((char **)source, dest, len * sizeof(char *));
}

static void array_insert_front(
        char *insert[], int64_t insert_len,
        char *const source[], int64_t source_len,
        char *dest[]) {
    int64_t i;

    for (i = 0; i < insert_len; i++) {
        dest[i] = insert[i];
    }

    for (i = insert_len; i < source_len + insert_len; i++) {
        dest[i] = source[i - insert_len];
    }
}

static int cmdline_argc(char *buf, ssize_t size) {
    int argc = 0;
    int whitespace = 1;

    int i;
    for (i = 2; i < size; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            return argc;
        } else if (buf[i] != ' ' && buf[i] != '\t') {
            if (whitespace) {
                argc++;
                whitespace = 0;
            }
        } else {
            whitespace = 1;
        }
    }

    return argc;
}

static void cmdline_extract(char *buf, ssize_t size, char **dest) {
    int argc = 0;
    int whitespace = 1;

    int i;
    for (i = 2; i < size; i++) {
        if (buf[i] == '\r' || buf[i] == '\n') {
            buf[i] = '\0';
            return;
        } else if (buf[i] != ' ' && buf[i] != '\t') {
            if (whitespace) {
                dest[argc] = buf + i;
                argc++;
                whitespace = 0;
            }
        } else {
            buf[i] = '\0';
            whitespace = 1;
        }
    }

    buf[size -1] = '\0';
    return;
}

static void debug_exec(const char *pathname, char *const argv[],
                       char *const envp[]) {
    int64_t i;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": recurse execve(%s, [ ", pathname?pathname:"NULL");

    for (i = 0; argv[i]; i++) {
        debug(DEBUG_LEVEL_VERBOSE, "%s, ", argv[i]);
    }

    debug(DEBUG_LEVEL_VERBOSE, "], envp)\n");
}

static ssize_t read_full(int fd, char *buf, size_t count)
{
    ssize_t ret = 0;
    ssize_t total = 0;

    while (count) {
        ret = read(fd, buf, count);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        } else if (ret == 0) {
            break;
        }

        count -= ret;
        buf += ret;
        total += ret;
    }

    return total;
}

static int handle_execve(const char *pathname, char *const exec_argv[],
                         char *const envp[]) {
    int fd;
    int _errno = 0;
    ssize_t ret, size;
    int64_t exec_argc;
    char buf[BUF_SIZE];

    if (!function_enter() || !pathname) {
        LOAD_EXECVE_FUNC();
        return _execve(pathname, exec_argv, envp);
    }

    MANGLE_PATH(pathname);

    exec_argc = array_len(exec_argv);
    if (exec_argc < 0) {
        errno = E2BIG;
        goto err;
    }

    LOAD_ACCESS_FUNC();
    ret = _access(pathname, X_OK);
    if (ret < 0) {
        goto err;
    }

    LOAD_OPEN_FUNC();
    fd = _open(pathname, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        goto err;
    }

    ret = read_full(fd, buf, BUF_SIZE);
    _errno = errno;
    LOAD_CLOSE_FUNC();
    _close(fd);
    if (ret < 0) {
        errno = _errno;
        goto err;
    }
    size = ret;

    if (size < 2) {
        errno = ENOEXEC;
        goto err;
    }

    if (buf[0] == '#' && buf[1] == '!') {
        int sh_argc = cmdline_argc(buf, size);
        if (sh_argc == 0) {
            errno = ENOEXEC;
            goto err;
        }

        int64_t argc = exec_argc + sh_argc;
        char *_argv[argc +1];
        char **argv = _argv;

        cmdline_extract(buf, size, argv);
        array_copy(exec_argv, argv + sh_argc, exec_argc);
        argv[sh_argc] = (char *) pathname;
        argv[argc] = NULL;
        pathname = argv[0];

        function_exit();

        debug_exec(pathname, argv, envp);
        return handle_execve(pathname, argv, envp);
    }

    LOAD_EXECVE_FUNC();
    ret = _execve(pathname, exec_argv, envp);

    function_exit();

    return ret;

 err:
    function_exit();
    return -1;
}

/* The file is accessible but it is not an executable file.  Invoke
   the shell to interpret it as a script.  */
static void maybe_script_execute(const char *file, char *const argv[],
                                 char *const envp[]) {
    int64_t argc;

    argc = array_len(argv);
    if (argc >= INT_MAX -1) {
        errno = E2BIG;
        return;
    }

    /* Construct an argument list for the shell based on original arguments:
     1. Empty list (argv = { NULL }, argc = 1 }: new argv will contain 3
    arguments - default shell, script to execute, and ending NULL.
     2. Non empty argument list (argc = { ..., NULL }, argc > 1}: new argv
    will contain also the default shell and the script to execute.  It
    will also skip the script name in arguments and only copy script
    arguments.  */
    char *new_argv[argc > 1 ? 2 + argc : 3];
    new_argv[0] = (char *) "/bin/sh";
    new_argv[1] = (char *) file;
    if (argc > 1) {
        array_copy(new_argv + 2, (char **) argv + 1, argc);
    } else {
        new_argv[2] = NULL;
    }

    /* Execute the shell.  */
    handle_execve(new_argv[0], new_argv, envp);
}

static int _handle_execvpe(const char *file, char *const argv[], char *const envp[],
                           int exec_script) {
    /* We check the simple case first. */
    if (*file == '\0') {
        errno = ENOENT;
        return -1;
    }

    /* Don't search when it contains a slash.  */
    if (strchr(file, '/') != NULL) {
        handle_execve(file, argv, envp);

        if (errno == ENOEXEC && exec_script) {
            maybe_script_execute(file, argv, envp);
        }

        return -1;
    }

    size_t path_buf_size = confstr(_CS_PATH, NULL, 0);
    if (path_buf_size == 0 || path_buf_size > (64*1024)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    char path_buf[path_buf_size];
    const char *path = getenv("PATH");
    if (!path) {
        confstr(_CS_PATH, path_buf, path_buf_size);
        path = path_buf;
    }
    /* Although GLIBC does not enforce NAME_MAX, we set it as the maximum
     size to avoid unbounded stack allocation.  Same applies for
     PATH_MAX.  */
    size_t file_len = strnlen(file, NAME_MAX) + 1;
    size_t path_len = strnlen(path, PATH_MAX - 1) + 1;

    /* NAME_MAX does not include the terminating null character.  */
    if ((file_len - 1 > NAME_MAX) || path_len + file_len + 1 > (64*1024)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    const char *subp;
    int got_eacces = 0;
    /* The resulting string maximum size would be potentially a entry
     in PATH plus '/' (path_len + 1) and then the the resulting file name
     plus '\0' (file_len since it already accounts for the '\0').  */
    char buffer[path_len + file_len + 1];
    for (const char *p = path; ; p = subp) {
        subp = strchrnul(p, ':');

        /* PATH is larger than PATH_MAX and thus potentially larger than
        the stack allocation.  */
        if (subp - p >= path_len) {
            /* If there is only one path, bail out.  */
            if (*subp == '\0') break;
            /* Otherwise skip to next one.  */
            continue;
        }

        /* Use the current path entry, plus a '/' if nonempty, plus the file to
         execute.  */
        char *pend = mempcpy(buffer, p, subp - p);
        *pend = '/';
        memcpy(pend + (p < subp), file, file_len);

        handle_execve(buffer, argv, envp);

        if (errno == ENOEXEC && exec_script) {
            /* This has O(P*C) behavior, where P is the length of the path and C
               is the argument count.  A better strategy would be allocate the
               substitute argv and reuse it each time through the loop (so it
               behaves as O(P+C) instead.  */
            maybe_script_execute(buffer, argv, envp);
        }

        switch (errno)
        {
            case EACCES:
                /* Record that we got a 'Permission denied' error.  If we end
                 up finding no executable we can use, we want to diagnose
                 that we did find one but were denied access.  */
                got_eacces = 1;
            case ENOENT:
            case ESTALE:
            case ENOTDIR:
                /* Those errors indicate the file is missing or not executable
                 by us, in which case we want to just try the next path
                 directory.  */
            case ENODEV:
            case ETIMEDOUT:
                /* Some strange filesystems like AFS return even
                 stranger error numbers.  They cannot reasonably mean
                 anything else so ignore those, too.  */
                break;

            default:
                /* Some other error means we found an executable file, but
                 something went wrong executing it; return the error to our
                 caller.  */
                return -1;
        }

        if (*subp++ == '\0') break;
    }

    /* We tried every element and none of them worked.  */
    if (got_eacces) {
        /* At least one failure was due to permissions, so report that
           error.  */
        errno = EACCES;
    }

    return -1;
}

static int handle_execvpe(const char *pathname, char *const argv[],
                          char *const envp[]) {
    return _handle_execvpe(pathname, argv, envp, 1);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execve(%s)\n", pathname?pathname:"NULL");

    return handle_execve(pathname, argv, envp);
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execveat(%s)\n", pathname?pathname:"NULL");

    LOAD_EXECVEAT_FUNC();
    if (!pathname || pathname[0] != '/') {
        return _execveat(dirfd, pathname, argv, envp, flags);
    }

    MANGLE_PATH(pathname);
    return _execveat(dirfd, pathname, argv, envp, flags);
}

int execl(const char *pathname, const char *arg, ... /*, (char *) NULL */) {
    int64_t argc;
    va_list args;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execl(%s)\n", pathname?pathname:"NULL");

    va_start(args, arg);
    for (argc = 1; va_arg(args, const char *); argc++) {
        if (argc == INT_MAX) {
            va_end(args);
            errno = E2BIG;
            return -1;
        }
    }
    va_end(args);

    int64_t i;
    char *argv[argc + 1];
    va_start(args, arg);
    argv[0] = (char *) arg;
    for (i = 1; i <= argc; i++) {
        argv[i] = va_arg(args, char *);
    }
    va_end(args);

    return handle_execve(pathname, argv, environ);
}

int execlp(const char *file, const char *arg, ... /*, (char *) NULL */) {
    int64_t argc;
    va_list args;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execlp(%s)\n", file?file:"NULL");

    va_start(args, arg);
    for (argc = 1; va_arg(args, const char *); argc++) {
        if (argc == INT_MAX) {
            va_end(args);
            errno = E2BIG;
            return -1;
        }
    }
    va_end(args);

    int64_t i;
    char *argv[argc + 1];
    va_start(args, arg);
    argv[0] = (char *) arg;
    for (i = 1; i <= argc; i++) {
        argv[i] = va_arg(args, char *);
    }
    va_end(args);

    return handle_execvpe(file, argv, environ);
}

int execle(const char *pathname, const char *arg, ... /*, (char *) NULL, char *const envp[] */) {
    int64_t argc;
    va_list args;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execle(%s)\n", pathname?pathname:"NULL");

    va_start(args, arg);
    for (argc = 1; va_arg(args, const char *); argc++) {
        if (argc == INT_MAX) {
            va_end(args);
            errno = E2BIG;
            return -1;
        }
    }
    va_end(args);

    int64_t i;
    char *argv[argc + 1];
    char **envp;
    va_start(args, arg);
    argv[0] = (char *) arg;
    for (i = 1; i <= argc; i++) {
        argv[i] = va_arg(args, char *);
    }
    envp = va_arg(args, char **);
    va_end(args);

    return handle_execve(pathname, argv, envp);
}

int execv(const char *pathname, char *const argv[]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execv(%s)\n", pathname?pathname:"NULL");

    return handle_execve(pathname, argv, environ);
}

int execvp(const char *pathname, char *const argv[]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execvp(%s)\n", pathname?pathname:"NULL");

    return handle_execvpe(pathname, argv, environ);
}

#ifdef _GNU_SOURCE
int execvpe(const char *file, char *const argv[], char *const envp[]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": execvpe(%s)\n", file?file:"NULL");

    return handle_execvpe(file, argv, envp);
}
#endif

int posix_spawn(pid_t *restrict pid, const char *restrict path,
                const posix_spawn_file_actions_t *restrict file_actions,
                const posix_spawnattr_t *restrict attrp,
                char *const argv[restrict],
                char *const envp[restrict]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": posix_spawn(%s)\n", path?path:"NULL");

    LOAD_POSIX_SPAWN_FUNC();
    MANGLE_PATH(path);
    return _posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

int posix_spawnp(pid_t *restrict pid, const char *restrict file,
                 const posix_spawn_file_actions_t *restrict file_actions,
                 const posix_spawnattr_t *restrict attrp,
                 char *const argv[restrict],
                 char *const envp[restrict]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": posix_spawnp(%s)\n", file?file:"NULL");

    LOAD_POSIX_SPAWNP_FUNC();
    MANGLE_PATH(file);
    return _posix_spawnp(pid, file, file_actions, attrp, argv, envp);
}
