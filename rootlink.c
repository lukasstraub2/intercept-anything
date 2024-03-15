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

void *rt_malloc(size_t size) {
    void *ret;

    ret = malloc(size);

    if (!ret) {
        abort();
    }

    return ret;
}

char *rt_strdup(const char *str) {
    char *ret;

    ret = strdup(str);

    if (!ret) {
        abort();
    }

    return ret;
}

char* rt_strdup_cat(const char *a, const char *b) {
    int a_len, b_len;
    char *ret;

    a_len = strlen(a);
    b_len = strlen(b);

    ret = rt_malloc(a_len + b_len + 1);
    memcpy(ret, a, a_len);
    memcpy(ret + a_len, b, b_len + 1);

    return ret;
}

static int strcmp_prefix(const char *a, const char *b) {
    return strncmp(a, b, strlen(b));
}

int mkpath(char* file_path, mode_t mode) {
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

// TODO: implement all path based apis

static char *mkfakelink(const char *path) {
    int ret;
    char *linkpath = NULL;
    char *target = NULL;
    char *dir_end;

    linkpath = rt_strdup_cat(PREFIX "/tmp/rootlink", path);

    ret = faccessat(-1, linkpath, F_OK, AT_SYMLINK_NOFOLLOW);
    if (ret == 0) {
        return linkpath;
    }

    dir_end = strrchr(linkpath, '/');
    *dir_end = '\0';
    ret = mkpath(linkpath, 7777);
    *dir_end = '/';

    if (ret < 0) {
        goto err;
    }

    target = rt_strdup_cat(PREFIX, path);

    ret = symlink(target, linkpath);
    if (ret < 0) {
        goto err;
    }

    free(target);
    return linkpath;

err:
    free(linkpath);
    free(target);
    return NULL;
}

static int handle_path(const char *path) {
    // Android does have /bin/sh
    return !strcmp(path, "/bin/bash") || !strcmp(path, "/usr/bin/env") ||
            !strcmp(path, "/bin/pwd") || !strcmp(path, "/bin/ln") ||
            !strcmp_prefix(path, "/usr/include");
}

static char *mangle_path(const char *path) {
    if (!handle_path(path)) {
        return rt_strdup(path);
    }

    return mkfakelink(path);
}

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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _open(path, flags, mode);

    free(path);
    return ret;
}

int __open_2(const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open_2(%s)\n", pathname?pathname:"NULL");

    load___open_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname) {
        return ___open_2(pathname, flags);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = ___open_2(path, flags);

    free(path);
    return ret;
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

    load_openat_func();
    if (!pathname || pathname[0] != '/') {
        return _openat(dirfd, pathname, flags, mode);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _openat(dirfd, path, flags, mode);

    free(path);
    return ret;
}

int __openat_2(int dirfd, const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat_2(%s)\n", pathname?pathname:"NULL");

    load___openat_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat_2(dirfd, pathname, flags);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = ___openat_2(dirfd, path, flags);

    free(path);
    return ret;
}

#endif

int opendir(const char *pathname) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": opendir(%s)\n", pathname?pathname:"NULL");

    load_opendir_func();
    if (!pathname) {
        return _opendir(pathname);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _opendir(path);

    free(path);
    return ret;
}

int access(const char *pathname, int mode) {
    int ret;

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": access(%s)\n", pathname?pathname:"NULL");

    load_access_func();
    if (!function_enter() || !pathname) {
        return _access(pathname, mode);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    ret = _access(path, mode);
    free(path);

    function_exit();

    return ret;
}

int stat(const char *pathname, struct stat *buf) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": stat(%s)\n", pathname?pathname:"NULL");

    load_stat_func();
    if (!pathname) {
        return _stat(pathname, buf);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _stat(path, buf);

    free(path);
    return ret;
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _stat64(path, buf);

    free(path);
    return ret;
}
#undef open64
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _open64(path, flags, mode);

    free(path);
    return ret;
}

int __open64_2(const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __open64_2(%s)\n", pathname?pathname:"NULL");

    load___open64_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname) {
        return ___open64_2(pathname, flags);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = ___open64_2(path, flags);

    free(path);
    return ret;
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

    load_openat64_func();
    if (!pathname || pathname[0] != '/') {
        return _openat64(dirfd, pathname, flags, mode);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _openat64(dirfd, path, flags, mode);

    free(path);
    return ret;
}

int __openat64_2(int dirfd, const char *pathname, int flags) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __openat64_2(%s)\n", pathname?pathname:"NULL");

    load___openat64_2_func();
    if (OPEN_NEEDS_MODE(flags) || !pathname || pathname[0] != '/') {
        return ___openat64_2(dirfd, pathname, flags);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = ___openat64_2(dirfd, path, flags);

    free(path);
    return ret;
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = ___xstat(ver, path, buf);

    free(path);
    return ret;
}

#ifdef HAVE_OPEN64

int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    debug(DEBUG_LEVEL_VERBOSE, __FILE__": __xstat64(%s)\n", pathname?pathname:"NULL");

    load_xstat64_func();
    if (!pathname) {
        return ___xstat64(ver, pathname, buf);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = ___xstat64(ver, path, buf);

    free(path);
    return ret;
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _statx(dirfd, path, flags, mask, statxbuf);

    free(path);
    return ret;
}

#endif

FILE* fopen(const char *pathname, const char *mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen(%s)\n", pathname?pathname:"NULL");

    load_fopen_func();
    if (!pathname) {
        return _fopen(pathname, mode);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return NULL;
    }

    FILE *ret = _fopen(path, mode);

    free(path);
    return ret;
}

#ifdef HAVE_OPEN64
#undef fopen64
FILE *fopen64(const char *__restrict pathname, const char *__restrict mode) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": fopen64(%s)\n", pathname?pathname:"NULL");

    load_fopen64_func();
    if (!pathname) {
        return _fopen64(pathname, mode);
    }

    char *path = mangle_path(pathname);
    if (!path) {
        return NULL;
    }

    FILE *ret = _fopen64(path, mode);

    free(path);
    return ret;
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    exec_argc = array_len(exec_argv);
    if (exec_argc < 0) {
        errno = E2BIG;
        goto err;
    }

    load_access_func();
    ret = _access(path, X_OK);
    if (ret < 0) {
        goto err;
    }

    load_open_func();
    fd = _open(path, O_RDONLY | O_CLOEXEC, 0);
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
        argv[sh_argc] = (char *) path;
        argv[argc] = NULL;
        path = argv[0];

        function_exit();

        debug_exec(path, argv, envp);
        ret = handle_execve(path, argv, envp);

        free(path);
        return ret;
    }

    load_execve_func();
    ret = _execve(path, exec_argv, envp);

    free(path);
    function_exit();

    return ret;

 err:
    free(path);
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    int ret = _execveat(dirfd, path, argv, envp, flags);

    free(path);
    return ret;
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

    char *path = mangle_path(pathname);
    if (!path) {
        return -1;
    }

    load_posix_spawn_func();
    int ret = _posix_spawn(pid, path, file_actions, attrp, argv, envp);

    free(path);
    return ret;
}

int posix_spawnp(pid_t *restrict pid, const char *restrict filename,
                 const posix_spawn_file_actions_t *restrict file_actions,
                 const posix_spawnattr_t *restrict attrp,
                 char *const argv[restrict],
                 char *const envp[restrict]) {

    debug(DEBUG_LEVEL_VERBOSE, __FILE__": posix_spawnp(%s)\n", filename?filename:"NULL");

    char *path = mangle_path(filename);
    if (!path) {
        return -1;
    }

    load_posix_spawnp_func();
    int ret = _posix_spawnp(pid, path, file_actions, attrp, argv, envp);

    free(path);
    return ret;
}
