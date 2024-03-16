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

#define DEBUG_ENV "ROOTLINK_DEBUG"
#include "config.h"
#include "debug.h"
#include "parent_open.h"
#include "parent_close.h"
#include "parent_stat.h"
#include "parent_exec.h"
#include "parent_glob.h"

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

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define min(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

static size_t concat(char *out, size_t out_len, const char *a, const char *b) {
    const size_t a_len = strlen(a);
    const size_t b_len = strlen(b);

    if (!out) {
        return a_len + b_len +1;
    }

    if (a_len +1 > out_len) {
        memcpy(out, a, out_len);
        out[out_len -1] = '\0';
        return a_len + b_len +1;
    }

    memcpy(out, a, a_len +1);
    memcpy(out + a_len, b, min(b_len +1, out_len - a_len));
    out[out_len -1] = '\0';

    return a_len + b_len +1;
}

static int strcmp_prefix(const char *a, const char *b) {
    return strncmp(a, b, strlen(b));
}

static int mkpath(char* file_path, mode_t mode) {
    for (char* p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                return -1;
            }
        }
        *p = '/';
    }
    return 0;
}

static int mkfakelink(char *linkpath, size_t linkpath_len, const char *path) {
    int ret;
    size_t len;

    len = concat(linkpath, linkpath_len, PREFIX "/tmp/rootlink", path);
    if (len > linkpath_len) {
        errno = ENAMETOOLONG;
        return -1;
    }

    ret = faccessat(-1, linkpath, F_OK, AT_SYMLINK_NOFOLLOW);
    if (ret == 0) {
        return 0;
    }

    ret = mkpath(linkpath, 0777);
    if (ret < 0) {
        return -1;
    }

    char target[linkpath_len];
    len = concat(target, linkpath_len, PREFIX, path);
    if (len > linkpath_len) {
        errno = ENAMETOOLONG;
        return -1;
    }

    ret = symlink(target, linkpath);
    if (ret < 0) {
        return -1;
    }

    return 0;
}

static int handle_path(const char *path) {
    // Android does have /bin/sh
    return !strcmp(path, "/bin/bash") || !strcmp(path, "/usr/bin/env") ||
            !strcmp(path, "/bin/pwd") || !strcmp(path, "/bin/ln") ||
            !strcmp_prefix(path, "/usr/include");
}

static int mangle_path(char *out, size_t out_len, const char *path) {
    if (!handle_path(path)) {
        size_t path_len = strlen(path);
        if (path_len +1 > out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        memcpy(out, path, path_len +1);
        return 0;
    }

    return mkfakelink(out, out_len, path);
}

#define MANGLE_PATH(__path) \
    char path_buf[BUF_SIZE]; \
    if (mangle_path(path_buf, BUF_SIZE, (__path)) < 0) { \
        return -1; \
    } \
    (__path) = path_buf;

int open(const char *pathname, int flags, ...) {
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": open(%s)\n", pathname?pathname:"NULL");

    if (OPEN_NEEDS_MODE(flags)) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = (mode_t) va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    load_open_func();
    if (!pathname) {
        return _open(pathname, flags, mode);
    }

    MANGLE_PATH(pathname)
    return _open(pathname, flags, mode);
}

int __open_2(const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open_2(%s)\n", pathname?pathname:"NULL");

    load___open_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname) {
        return ___open_2(pathname, flags);
    }

    MANGLE_PATH(pathname);
    return ___open_2(pathname, flags);
}

#ifdef HAVE_OPEN64
int open64(const char *pathname, int flags, ...) {
    va_list args;
    mode_t mode = 0;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": open64(%s)\n", pathname?pathname:"NULL");

    if (OPEN_NEEDS_MODE(flags)) {
        va_start(args, flags);
        if (sizeof(mode_t) < sizeof(int))
            mode = va_arg(args, int);
        else
            mode = va_arg(args, mode_t);
        va_end(args);
    }

    load_open64_func();
    if (!pathname) {
        return _open64(pathname, flags, mode);
    }

    MANGLE_PATH(pathname);
    return _open64(pathname, flags, mode);
}

int __open64_2(const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open64_2(%s)\n", pathname?pathname:"NULL");

    load___open64_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname) {
        return ___open64_2(pathname, flags);
    }

    MANGLE_PATH(pathname);
    return ___open64_2(pathname, flags);
}
#endif

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

    load_openat_func();
    if (!pathname || pathname[0] != '/') {
        return _openat(dirfd, pathname, flags, mode);
    }

    MANGLE_PATH(pathname);
    return _openat(dirfd, pathname, flags, mode);
}

int __openat_2(int dirfd, const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat_2(%s)\n", pathname?pathname:"NULL");

    load___openat_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat_2(dirfd, pathname, flags);
    }

    MANGLE_PATH(pathname);
    return ___openat_2(dirfd, pathname, flags);
}

#ifdef HAVE_OPEN64
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

    load_openat64_func();
    if (!pathname || pathname[0] != '/') {
        return _openat64(dirfd, pathname, flags, mode);
    }

    MANGLE_PATH(pathname);
    return _openat64(dirfd, pathname, flags, mode);
}

int __openat64_2(int dirfd, const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat64_2(%s)\n", pathname?pathname:"NULL");

    load___openat64_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat64_2(dirfd, pathname, flags);
    }

    MANGLE_PATH(pathname);
    return ___openat64_2(dirfd, pathname, flags);
}
#endif
#endif

FILE* fopen(const char *pathname, const char *mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen(%s)\n", pathname?pathname:"NULL");

    load_fopen_func();
    if (!pathname) {
        return _fopen(pathname, mode);
    }

    char path_buf[BUF_SIZE];
    if (mangle_path(path_buf, BUF_SIZE, pathname) < 0) {
        return NULL;
    }
    return _fopen(path_buf, mode);
}

#ifdef HAVE_OPEN64
#undef fopen64
FILE *fopen64(const char *__restrict pathname, const char *__restrict mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen64(%s)\n", pathname?pathname:"NULL");

    load_fopen64_func();
    if (!pathname) {
        return _fopen64(pathname, mode);
    }

    char path_buf[BUF_SIZE];
    if (mangle_path(path_buf, BUF_SIZE, pathname) < 0) {
        return NULL;
    }
    return _fopen64(path_buf, mode);
}
#endif

DIR *opendir(const char *pathname) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": opendir(%s)\n", pathname?pathname:"NULL");

    load_opendir_func();
    if (!pathname) {
        return _opendir(pathname);
    }

    char path_buf[BUF_SIZE];
    if (mangle_path(path_buf, BUF_SIZE, pathname) < 0) {
        return NULL;
    }
    return _opendir(path_buf);
}

int stat(const char *pathname, struct stat *buf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat(%s)\n", pathname?pathname:"NULL");

    load_stat_func();
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

    load_stat64_func();
    if (!pathname) {
        return _stat64(pathname, buf);
    }

    MANGLE_PATH(pathname);
    return _stat64(pathname, buf);
}
#endif

#ifdef _STAT_VER
int __xstat(int ver, const char *pathname, struct stat *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat(%s)\n", pathname?pathname:"NULL");

    load_xstat_func();
    if (!pathname) {
        return ___xstat(ver, pathname, buf);
    }

    MANGLE_PATH(pathname);
    return ___xstat(ver, pathname, buf);
}

#ifdef HAVE_OPEN64
int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat64(%s)\n", pathname?pathname:"NULL");

    load_xstat64_func();
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

    load_statx_func();
    if (!pathname || pathname[0] != '/') {
        return _statx(dirfd, pathname, flags, mask, statxbuf);
    }

    MANGLE_PATH(pathname);
    return _statx(dirfd, pathname, flags, mask, statxbuf);
}
#endif

int lstat(const char *restrict pathname, struct stat *restrict statbuf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": lstat(%s)\n", pathname?pathname:"NULL");

    load_lstat_func();
    if (!pathname) {
        return _lstat(pathname, statbuf);
    }

    MANGLE_PATH(pathname);
    return _lstat(pathname, statbuf);
}
#ifdef HAVE_OPEN64
int lstat64(const char *restrict pathname, struct stat64 *restrict statbuf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": lstat64(%s)\n", pathname?pathname:"NULL");

    load_lstat64_func();
    if (!pathname) {
        return _lstat64(pathname, statbuf);
    }

    MANGLE_PATH(pathname);
    return _lstat64(pathname, statbuf);
}
#endif

int fstatat(int dirfd, const char *restrict pathname,
            struct stat *restrict statbuf, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fstatat(%s)\n", pathname?pathname:"NULL");

    load_fstatat_func();
    if (!pathname || pathname[0] != '/') {
        return _fstatat(dirfd, pathname, statbuf, flags);
    }

    MANGLE_PATH(pathname);
    return _fstatat(dirfd, pathname, statbuf, flags);
}
#ifdef HAVE_OPEN64
int fstatat64(int dirfd, const char *restrict pathname,
              struct stat64 *restrict statbuf, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fstatat64(%s)\n", pathname?pathname:"NULL");

    load_fstatat64_func();
    if (!pathname || pathname[0] != '/') {
        return _fstatat64(dirfd, pathname, statbuf, flags);
    }

    MANGLE_PATH(pathname);
    return _fstatat64(dirfd, pathname, statbuf, flags);
}
#endif

ssize_t readlink(const char *restrict pathname,
                 char *restrict buf, size_t bufsiz) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": readlink(%s)\n", pathname?pathname:"NULL");

    load_readlink_func();
    if (!pathname) {
        return _readlink(pathname, buf, bufsiz);
    }

    MANGLE_PATH(pathname);
    return _readlink(pathname, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char *restrict pathname,
                   char *restrict buf, size_t bufsiz) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": readlinkat(%s)\n", pathname?pathname:"NULL");

    load_readlinkat_func();
    if (!pathname || pathname[0] != '/') {
        return _readlinkat(dirfd, pathname, buf, bufsiz);
    }

    MANGLE_PATH(pathname);
    return _readlinkat(dirfd, pathname, buf, bufsiz);
}

char *realpath(const char *restrict pathname, char *restrict resolved_path) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": realpath(%s)\n", pathname?pathname:"NULL");

    load_realpath_func();
    if (!pathname) {
        return _realpath(pathname, resolved_path);
    }

    char path_buf[BUF_SIZE];
    if (mangle_path(path_buf, BUF_SIZE, pathname) < 0) {
        return NULL;
    }
    return _realpath(path_buf, resolved_path);
}

#ifdef _GNU_SOURCE
char *canonicalize_file_name(const char *pathname) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": canonicalize_file_name(%s)\n", pathname?pathname:"NULL");

    load_canonicalize_file_name_func();
    if (!pathname) {
        return _canonicalize_file_name(pathname);
    }

    char path_buf[BUF_SIZE];
    if (mangle_path(path_buf, BUF_SIZE, pathname) < 0) {
        return NULL;
    }
    return _canonicalize_file_name(path_buf);
}
#endif


int access(const char *pathname, int mode) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": access(%s)\n", pathname?pathname:"NULL");

    load_access_func();
    if (!function_enter() || !pathname) {
        return _access(pathname, mode);
    }

    MANGLE_PATH(pathname);
    ret = _access(pathname, mode);

    function_exit();

    return ret;
}

int faccessat(int dirfd, const char *pathname, int mode, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": faccessat(%s)\n", pathname?pathname:"NULL");

    load_faccessat_func();
    if (!pathname || pathname[0] != '/') {
        return _faccessat(dirfd, pathname, mode, flags);
    }

    MANGLE_PATH(pathname);
    return _faccessat(dirfd, pathname, mode, flags);
}

#ifdef _GNU_SOURCE
int euidaccess(const char *pathname, int mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": euidaccess(%s)\n", pathname?pathname:"NULL");

    load_euidaccess_func();
    if (!pathname) {
        return _euidaccess(pathname, mode);
    }

    MANGLE_PATH(pathname);
    return _euidaccess(pathname, mode);
}

int eaccess(const char *pathname, int mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": eaccess(%s)\n", pathname?pathname:"NULL");

    load_eaccess_func();
    if (!pathname) {
        return _eaccess(pathname, mode);
    }

    MANGLE_PATH(pathname);
    return _eaccess(pathname, mode);
}
#endif

static int64_t array_len(char *const array[]) {
    int64_t len;

    for (len = 0; array[len]; len++) {
        if (len == INT_MAX) {
            return -1;
        }
    }

    return len;
}

static void array_copy(char *dest[], char *const source[], int64_t len) {
    memcpy(dest, source, len * sizeof(char *));
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
        load_execve_func();
        return _execve(pathname, exec_argv, envp);
    }

    MANGLE_PATH(pathname);

    exec_argc = array_len(exec_argv);
    if (exec_argc < 0) {
        errno = E2BIG;
        goto err;
    }

    load_access_func();
    ret = _access(pathname, X_OK);
    if (ret < 0) {
        goto err;
    }

    load_open_func();
    fd = _open(pathname, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        goto err;
    }

    ret = read_full(fd, buf, BUF_SIZE);
    _errno = errno;
    load_close_func();
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
        array_copy(argv + sh_argc, exec_argv, exec_argc);
        argv[sh_argc] = (char *) pathname;
        argv[argc] = NULL;
        pathname = argv[0];

        function_exit();

        debug_exec(pathname, argv, envp);
        return handle_execve(pathname, argv, envp);
    }

    load_execve_func();
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
        array_copy(new_argv + 2, argv + 1, argc);
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

    load_execveat_func();
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

int posix_spawn(pid_t *restrict pid, const char *restrict pathname,
                const posix_spawn_file_actions_t *restrict file_actions,
                const posix_spawnattr_t *restrict attrp,
                char *const argv[restrict],
                char *const envp[restrict]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": posix_spawn(%s)\n", pathname?pathname:"NULL");

    MANGLE_PATH(pathname);
    load_posix_spawn_func();
    return _posix_spawn(pid, pathname, file_actions, attrp, argv, envp);
}

int posix_spawnp(pid_t *restrict pid, const char *restrict filename,
                 const posix_spawn_file_actions_t *restrict file_actions,
                 const posix_spawnattr_t *restrict attrp,
                 char *const argv[restrict],
                 char *const envp[restrict]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": posix_spawnp(%s)\n", filename?filename:"NULL");

    MANGLE_PATH(filename);
    load_posix_spawnp_func();
    return _posix_spawnp(pid, filename, file_actions, attrp, argv, envp);
}

int system(const char* command) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": system(%s)\n", command?command:"NULL");

    load_system_func();
    return _system(command);
}

int glob(const char *restrict pattern, int flags,
         int (*errfunc)(const char *epath, int eerrno),
         glob_t *restrict pglob) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": glob(%s)\n", pattern?pattern:"NULL");

    load_glob_func();
    return _glob(pattern, flags, errfunc, pglob);
}
