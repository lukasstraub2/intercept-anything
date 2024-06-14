
#include "common.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

#include <fcntl.h>
#include <sys/xattr.h>

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "config.h"
#include "debug.h"
#include "util.h"

#define _INTERCEPT_GLIBC
#include "parent_open.h"
#include "parent_close.h"
#include "parent_stat.h"
#include "parent_exec.h"
#include "parent_glob.h"
#include "parent_link.h"
#include "parent_misc.h"
#include "parent_xattr.h"

#include "intercept.h"

#ifdef O_TMPFILE
#define OPEN_NEEDS_MODE(oflag) \
  (((oflag) & O_CREAT) != 0 || ((oflag) & O_TMPFILE) == O_TMPFILE)
#else
#define OPEN_NEEDS_MODE(oflag) (((oflag) & O_CREAT) != 0)
#endif

static const CallHandler bottom;
static const CallHandler *_next = NULL;

__attribute__((constructor))
static void init() {
	static int initialized = 0;

	if (initialized) {
		return;
	}
	initialized = 1;

	trace(": init()\n");

	parent_close_load();
	parent_exec_load();
	parent_glob_load();
	parent_open_load();
	parent_stat_load();
	parent_link_load();
	parent_misc_load();
	parent_xattr_load();

	_next = main_init(&bottom);
}

_Static_assert(sizeof(mode_t) >= sizeof(int), "sizeof(mode_t)");
__attribute__((visibility("default")))
int open(const char *pathname, int flags, ...) {
	va_list args;
	mode_t mode = 0;

	init();
	trace(": open(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags)) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	if (!pathname) {
		return _open(pathname, flags, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_PLAIN,
		.path = pathname,
		.flags = flags,
		.mode = mode,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
__attribute__((visibility("default")))
int __open_2(const char *pathname, int flags) {

	init();
	trace(": __open_2(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags) || !pathname) {
		return ___open_2(pathname, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_2,
		.path = pathname,
		.flags = flags,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#pragma GCC diagnostic pop

#ifdef HAVE_OPEN64
__attribute__((visibility("default")))
int open64(const char *pathname, int flags, ...) {
	va_list args;
	mode_t mode = 0;

	init();
	trace(": open64(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags)) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	if (!pathname) {
		return _open64(pathname, flags, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_64,
		.path = pathname,
		.flags = flags,
		.mode = mode,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
__attribute__((visibility("default")))
int __open64_2(const char *pathname, int flags) {

	init();
	trace(": __open64_2(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags) || !pathname) {
		return ___open64_2(pathname, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_64_2,
		.path = pathname,
		.flags = flags,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#pragma GCC diagnostic pop
#endif

#ifdef HAVE_OPENAT
__attribute__((visibility("default")))
int openat(int dirfd, const char *pathname, int flags, ...) {
	va_list args;
	mode_t mode = 0;

	init();
	trace(": openat(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags)) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	if (!pathname) {
		return _openat(dirfd, pathname, flags, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_AT,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.mode = mode,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
__attribute__((visibility("default")))
int __openat_2(int dirfd, const char *pathname, int flags) {

	init();
	trace(": __openat_2(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags) || !pathname) {
		return ___openat_2(dirfd, pathname, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_AT_2,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#pragma GCC diagnostic pop

#ifdef HAVE_OPEN64
__attribute__((visibility("default")))
int openat64(int dirfd, const char *pathname, int flags, ...) {
	va_list args;
	mode_t mode = 0;

	init();
	trace(": openat64(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags)) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	if (!pathname) {
		return _openat64(dirfd, pathname, flags, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_AT_64,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.mode = mode,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
__attribute__((visibility("default")))
int __openat64_2(int dirfd, const char *pathname, int flags) {

	init();
	trace(": __openat64_2(%s)\n", pathname?pathname:"NULL");

	if (OPEN_NEEDS_MODE(flags) || !pathname) {
		return ___openat64_2(dirfd, pathname, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_AT_64_2,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#pragma GCC diagnostic pop
#endif
#endif

__attribute__((visibility("default")))
int creat(const char *pathname, mode_t mode) {

	init();
	trace(": creat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_PLAIN,
		.path = pathname,
		.flags = O_CREAT | O_WRONLY | O_TRUNC,
		.mode = mode,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef HAVE_OPEN64
__attribute__((visibility("default")))
int creat64(const char *pathname, mode_t mode) {

	init();
	trace(": creat64(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _open64(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallOpen call = {
		.type = OPENTYPE_64,
		.path = pathname,
		.flags = O_CREAT | O_WRONLY | O_TRUNC,
		.mode = mode,
		.ret = &ret
	};
	_next->open(&ctx, _next->open_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

__attribute__((visibility("default")))
FILE* fopen(const char *pathname, const char *mode) {

	init();
	trace(": fopen(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _fopen(pathname, mode);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallFOpen call = {
		.fopen64 = 0,
		.path = pathname,
		.mode = mode,
		.ret = &ret
	};
	_next->fopen(&ctx, _next->fopen_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef HAVE_OPEN64
#undef fopen64
__attribute__((visibility("default")))
FILE *fopen64(const char *__restrict pathname, const char *__restrict mode) {

	init();
	trace(": fopen64(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _fopen64(pathname, mode);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallFOpen call = {
		.fopen64 = 1,
		.path = pathname,
		.mode = mode,
		.ret = &ret
	};
	_next->fopen(&ctx, _next->fopen_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

__attribute__((visibility("default")))
DIR *opendir(const char *pathname) {

	init();
	trace(": opendir(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _opendir(pathname);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallOpendir call = {
		.path = pathname,
		.ret = &ret
	};
	_next->opendir(&ctx, _next->opendir_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
int stat(const char *pathname, struct stat *buf) {

	init();
	trace(": stat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _stat(pathname, buf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_PLAIN,
		.path = pathname,
		.statbuf = buf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef HAVE_OPEN64
#undef stat64
__attribute__((visibility("default")))
#ifdef __GLIBC__
int stat64(const char *pathname, struct stat64 *buf) {
#else
int stat64(const char *pathname, struct stat *buf) {
#endif

	init();
	trace(": stat64(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _stat64(pathname, buf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_64,
		.path = pathname,
		.statbuf = buf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

#ifdef _STAT_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

__attribute__((visibility("default")))
int __xstat(int ver, const char *pathname, struct stat *buf) {

	init();
	trace(": __xstat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return ___xstat(ver, pathname, buf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE___X,
		.ver = ver,
		.path = pathname,
		.statbuf = buf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef HAVE_OPEN64
__attribute__((visibility("default")))
int __xstat64(int ver, const char *pathname, struct stat64 *buf) {

	init();
	trace(": __xstat64(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return ___xstat64(ver, pathname, buf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE___X_64,
		.ver = ver,
		.path = pathname,
		.statbuf = buf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

#pragma GCC diagnostic pop
#endif

__attribute__((visibility("default")))
int lstat(const char *restrict pathname, struct stat *restrict statbuf) {

	init();
	trace(": lstat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _lstat(pathname, statbuf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_L,
		.path = pathname,
		.statbuf = statbuf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef HAVE_OPEN64
__attribute__((visibility("default")))
int lstat64(const char *restrict pathname, struct stat64 *restrict statbuf) {

	init();
	trace(": lstat64(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _lstat64(pathname, statbuf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_L_64,
		.path = pathname,
		.statbuf = statbuf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

__attribute__((visibility("default")))
int fstatat(int dirfd, const char *restrict pathname,
			struct stat *restrict statbuf, int flags) {

	init();
	trace(": fstatat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _fstatat(dirfd, pathname, statbuf, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_AT,
		.dirfd = dirfd,
		.path = pathname,
		.statbuf = statbuf,
		.flags = flags,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef HAVE_OPEN64
__attribute__((visibility("default")))
int fstatat64(int dirfd, const char *restrict pathname,
			  struct stat64 *restrict statbuf, int flags) {

	init();
	trace(": fstatat64(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _fstatat64(dirfd, pathname, statbuf, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_AT_64,
		.dirfd = dirfd,
		.path = pathname,
		.statbuf = statbuf,
		.flags = flags,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

#ifdef _GNU_SOURCE
__attribute__((visibility("default")))
int statx(int dirfd, const char *restrict pathname, int flags,
		  unsigned int mask, struct statx *restrict statxbuf) {

	init();
	trace(": statx(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _statx(dirfd, pathname, flags, mask, statxbuf);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallStat call = {
		.type = STATTYPE_X,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.mask = mask,
		.statbuf = statxbuf,
		.ret = &ret
	};
	_next->stat(&ctx, _next->stat_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

__attribute__((visibility("default")))
ssize_t readlink(const char *restrict pathname,
				 char *restrict buf, size_t bufsiz) {

	init();
	trace(": readlink(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _readlink(pathname, buf, bufsiz);
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallReadlink call = {
		.at = 0,
		.path = pathname,
		.buf = buf,
		.bufsiz = bufsiz,
		.ret = &ret
	};
	_next->readlink(&ctx, _next->readlink_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
ssize_t readlinkat(int dirfd, const char *restrict pathname,
				   char *restrict buf, size_t bufsiz) {

	init();
	trace(": readlinkat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _readlinkat(dirfd, pathname, buf, bufsiz);
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallReadlink call = {
		.at = 1,
		.dirfd = dirfd,
		.path = pathname,
		.buf = buf,
		.bufsiz = bufsiz,
		.ret = &ret
	};
	_next->readlink(&ctx, _next->readlink_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
int access(const char *pathname, int mode) {

	init();
	trace(": access(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _access(pathname, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallAccess call = {
		.type = ACCESSTYPE_PLAIN,
		.path = pathname,
		.mode = mode,
		.ret = &ret
	};
	_next->access(&ctx, _next->access_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
int faccessat(int dirfd, const char *pathname, int mode, int flags) {

	init();
	trace(": faccessat(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _faccessat(dirfd, pathname, mode, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallAccess call = {
		.type = ACCESSTYPE_AT,
		.dirfd = dirfd,
		.path = pathname,
		.mode = mode,
		.flags = flags,
		.ret = &ret
	};
	_next->access(&ctx, _next->access_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef _GNU_SOURCE
__attribute__((visibility("default")))
int euidaccess(const char *pathname, int mode) {

	init();
	trace(": euidaccess(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _euidaccess(pathname, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallAccess call = {
		.type = ACCESSTYPE_EUID,
		.path = pathname,
		.mode = mode,
		.ret = &ret
	};
	_next->access(&ctx, _next->access_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
int eaccess(const char *pathname, int mode) {

	init();
	trace(": eaccess(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _eaccess(pathname, mode);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallAccess call = {
		.type = ACCESSTYPE_E,
		.path = pathname,
		.mode = mode,
		.ret = &ret
	};
	_next->access(&ctx, _next->access_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
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

static int line_size(char *buf, ssize_t size) {
	for (int i = 0; i < size; i++) {
		if (buf[i] == '\r' || buf[i] == '\n') {
			return i + 1;
		}
	}

	return size;
}

static int cmdline_argc(char *buf, ssize_t size) {
	int argc = 0;
	int whitespace = 1;

	for (int i = 2; i < size; i++) {
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

	for (int i = 2; i < size; i++) {
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

	trace(": recurse execve(%s, [ ", pathname?pathname:"NULL");

	for (i = 0; argv[i]; i++) {
		trace( "%s, ", argv[i]);
	}

	trace( "], envp)\n");
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

static int handle_execve(const char *pathname, char *const argv[],
						 char *const envp[]) {

	if (!pathname) {
		return _execve(pathname, argv, envp);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallExec call = {
		.type = EXECTYPE_EXECVE,
		.final = 0,
		.path = pathname,
		.argv = argv,
		.envp = envp,
		.ret = &ret
	};
	_next->exec(&ctx, _next->exec_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

static int handle_execveat(int dirfd, const char *pathname, char *const argv[],
						   char *const envp[], int flags) {

	if (!pathname) {
		return _execveat(dirfd, pathname, argv, envp, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallExec call = {
		.type = EXECTYPE_EXECVE_AT,
		.final = 0,
		.dirfd = dirfd,
		.path = pathname,
		.argv = argv,
		.envp = envp,
		.flags = flags,
		.ret = &ret
	};
	_next->exec(&ctx, _next->exec_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
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

__attribute__((visibility("default")))
int execve(const char *pathname, char *const argv[], char *const envp[]) {

	init();
	trace(": execve(%s)\n", pathname?pathname:"NULL");

	return handle_execve(pathname, argv, envp);
}

__attribute__((visibility("default")))
int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {

	init();
	trace(": execveat(%s)\n", pathname?pathname:"NULL");

	return handle_execveat(dirfd, pathname, argv, envp, flags);
}

__attribute__((visibility("default")))
int execl(const char *pathname, const char *arg, ... /*, (char *) NULL */) {
	int64_t argc;
	va_list args;

	init();
	trace(": execl(%s)\n", pathname?pathname:"NULL");

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

__attribute__((visibility("default")))
int execlp(const char *file, const char *arg, ... /*, (char *) NULL */) {
	int64_t argc;
	va_list args;

	init();
	trace(": execlp(%s)\n", file?file:"NULL");

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

__attribute__((visibility("default")))
int execle(const char *pathname, const char *arg, ... /*, (char *) NULL, char *const envp[] */) {
	int64_t argc;
	va_list args;

	init();
	trace(": execle(%s)\n", pathname?pathname:"NULL");

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

__attribute__((visibility("default")))
int execv(const char *pathname, char *const argv[]) {

	init();
	trace(": execv(%s)\n", pathname?pathname:"NULL");

	return handle_execve(pathname, argv, environ);
}

__attribute__((visibility("default")))
int execvp(const char *pathname, char *const argv[]) {

	init();
	trace(": execvp(%s)\n", pathname?pathname:"NULL");

	return handle_execvpe(pathname, argv, environ);
}

#ifdef _GNU_SOURCE
__attribute__((visibility("default")))
int execvpe(const char *file, char *const argv[], char *const envp[]) {

	init();
	trace(": execvpe(%s)\n", file?file:"NULL");

	return handle_execvpe(file, argv, envp);
}
#endif

typedef enum PosixType PosixType;
enum PosixType {
	POSIXTYPE_PLAIN,
	POSIXTYPE_P
};

static int posix_spawn_helper(PosixType type,
							  pid_t *restrict pid, const char *restrict filename,
							  const posix_spawn_file_actions_t *restrict file_actions,
							  const posix_spawnattr_t *restrict attrp,
							  char *const argv[restrict],
							  char *const envp[restrict]) {
	int64_t argc;

	argc = array_len(argv);
	if (argc >= INT_MAX -1) {
		errno = E2BIG;
		return -1;
	}

	/* Construct an argument list for the shell based on original arguments:
	 1. Empty list (argv = { NULL }, argc = 1 }: new argv will contain 3
	arguments - default shell, script to execute, and ending NULL.
	 2. Non empty argument list (argc = { ..., NULL }, argc > 1}: new argv
	will contain also the default shell and the script to execute.  It
	will also skip the script name in arguments and only copy script
	arguments.  */
	char *new_argv[argc > 1 ? 2 + argc : 3];
	new_argv[0] = (char *) (type == POSIXTYPE_PLAIN? "posix_spawn": "posix_spawnp");
	new_argv[1] = (char *) filename;
	if (argc > 1) {
		array_copy(new_argv + 2, argv, argc + 1);
	} else {
		new_argv[2] = NULL;
	}

	return _posix_spawn(pid, PREFIX "/opt/posix_spawnp_helper", file_actions,
						attrp, new_argv, envp);
}

__attribute__((visibility("default")))
int posix_spawn(pid_t *restrict pid, const char *restrict pathname,
				const posix_spawn_file_actions_t *restrict file_actions,
				const posix_spawnattr_t *restrict attrp,
				char *const argv[restrict],
				char *const envp[restrict]) {

	init();
	trace(": posix_spawn(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _posix_spawn(pid, pathname, file_actions, attrp, argv, envp);
	}

	return posix_spawn_helper(POSIXTYPE_PLAIN, pid, pathname, file_actions,
							  attrp, argv, envp);
}

__attribute__((visibility("default")))
int posix_spawnp(pid_t *restrict pid, const char *restrict filename,
				 const posix_spawn_file_actions_t *restrict file_actions,
				 const posix_spawnattr_t *restrict attrp,
				 char *const argv[restrict],
				 char *const envp[restrict]) {

	init();
	trace(": posix_spawnp(%s)\n", filename?filename:"NULL");

	if (!filename) {
		return _posix_spawnp(pid, filename, file_actions, attrp, argv, envp);
	}

	return posix_spawn_helper(POSIXTYPE_P, pid, filename, file_actions, attrp,
							  argv, envp);
}

__attribute__((visibility("default")))
int system(const char* command) {

	init();
	trace(": system(%s)\n", command?command:"NULL");

	return _system(command);
}

__attribute__((visibility("default")))
char *realpath(const char *restrict pathname, char *restrict resolved_path) {

	init();
	trace(": realpath(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _realpath(pathname, resolved_path);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallRealpath call = {
		.path = pathname,
		.out = resolved_path,
		.ret = &ret
	};
	_next->realpath(&ctx, _next->realpath_next, &call);
	errno = ret._errno;
	return ret.ret;
}

#ifdef _GNU_SOURCE
__attribute__((visibility("default")))
char *canonicalize_file_name(const char *pathname) {

	init();
	trace(": canonicalize_file_name(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _realpath(pathname, NULL);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallRealpath call = {
		.path = pathname,
		.out = NULL,
		.ret = &ret
	};
	_next->realpath(&ctx, _next->realpath_next, &call);
	errno = ret._errno;
	return ret.ret;
}
#endif

__attribute__((visibility("default")))
int glob(const char *restrict pattern, int flags,
		 int (*errfunc)(const char *epath, int eerrno),
		 glob_t *restrict pglob) {

	init();
	trace(": glob(%s)\n", pattern?pattern:"NULL");

	return _glob(pattern, flags, errfunc, pglob);
}

__attribute__((visibility("default")))
int link(const char *oldpath, const char *newpath) {

	init();
	trace(": link(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _link(oldpath, newpath);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 0,
		.oldpath = oldpath,
		.newpath = newpath,
		.ret = &ret
	};
	_next->link(&ctx, _next->link_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int linkat(int olddirfd, const char *oldpath,
		   int newdirfd, const char *newpath, int flags) {

	init();
	trace(": linkat(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _linkat(olddirfd, oldpath, newdirfd, newpath, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 1,
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.flags = flags,
		.ret = &ret
	};
	_next->link(&ctx, _next->link_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int symlink(const char *oldpath, const char *newpath) {

	init();
	trace(": symlink(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _symlink(oldpath, newpath);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 0,
		.oldpath = oldpath,
		.newpath = newpath,
		.ret = &ret
	};
	_next->symlink(&ctx, _next->symlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int symlinkat(const char *oldpath, int newdirfd, const char *newpath) {

	init();
	trace(": symlinkat(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _symlinkat(oldpath, newdirfd, newpath);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallLink call = {
		.at = 1,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.ret = &ret
	};
	_next->symlink(&ctx, _next->symlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int unlink(const char *pathname) {

	init();
	trace(": unlink(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _unlink(pathname);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallUnlink call = {
		.at = 0,
		.path = pathname,
		.ret = &ret
	};
	_next->unlink(&ctx, _next->unlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int unlinkat(int dirfd, const char *pathname, int flags) {

	init();
	trace(": unlink(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		return _unlinkat(dirfd, pathname, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallUnlink call = {
		.at = 1,
		.dirfd = dirfd,
		.path = pathname,
		.flags = flags,
		.ret = &ret
	};
	_next->unlink(&ctx, _next->unlink_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
ssize_t listxattr(const char *pathname, char *list, size_t size) {

	init();
	trace(": listxattr(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallListXattr call = {
		.type = XATTRTYPE_PLAIN,
		.path = pathname,
		.list = list,
		.size = size,
		.ret = &ret
	};
	_next->listxattr(&ctx, _next->listxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
ssize_t llistxattr(const char *pathname, char *list, size_t size) {

	init();
	trace(": llistxattr(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallListXattr call = {
		.type = XATTRTYPE_L,
		.path = pathname,
		.list = list,
		.size = size,
		.ret = &ret
	};
	_next->listxattr(&ctx, _next->listxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
ssize_t flistxattr(int fd, char *list, size_t size) {

	init();
	trace(": flistxattr(%d)\n", fd);

	if (fd < 0) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallListXattr call = {
		.type = XATTRTYPE_F,
		.fd = fd,
		.list = list,
		.size = size,
		.ret = &ret
	};
	_next->listxattr(&ctx, _next->listxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int setxattr(const char *pathname, const char *name,
			 const void *value, size_t size, int flags) {

	init();
	trace(": setxattr(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallSetXattr call = {
		.type = XATTRTYPE_PLAIN,
		.path = pathname,
		.name = name,
		.value = value,
		.size = size,
		.flags = flags,
		.ret = &ret
	};
	_next->setxattr(&ctx, _next->setxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int lsetxattr(const char *pathname, const char *name,
			  const void *value, size_t size, int flags) {

	init();
	trace(": lsetxattr(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallSetXattr call = {
		.type = XATTRTYPE_L,
		.path = pathname,
		.name = name,
		.value = value,
		.size = size,
		.flags = flags,
		.ret = &ret
	};
	_next->setxattr(&ctx, _next->setxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int fsetxattr(int fd, const char *name,
			  const void *value, size_t size, int flags) {

	init();
	trace(": fsetxattr(%d)\n", fd);

	if (fd < 0) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallSetXattr call = {
		.type = XATTRTYPE_F,
		.fd = fd,
		.name = name,
		.value = value,
		.size = size,
		.flags = flags,
		.ret = &ret
	};
	_next->setxattr(&ctx, _next->setxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
ssize_t getxattr(const char *pathname, const char *name,
				 void *value, size_t size) {

	init();
	trace(": getxattr(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallGetXattr call = {
		.type = XATTRTYPE_PLAIN,
		.path = pathname,
		.name = name,
		.value = value,
		.size = size,
		.ret = &ret
	};
	_next->getxattr(&ctx, _next->getxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
ssize_t lgetxattr(const char *pathname, const char *name,
				  void *value, size_t size) {

	init();
	trace(": lgetxattr(%s)\n", pathname?pathname:"NULL");

	if (!pathname) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallGetXattr call = {
		.type = XATTRTYPE_L,
		.path = pathname,
		.name = name,
		.value = value,
		.size = size,
		.ret = &ret
	};
	_next->getxattr(&ctx, _next->getxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
ssize_t fgetxattr(int fd, const char *name,
				  void *value, size_t size) {

	init();
	trace(": fgetxattr(%d)\n", fd);

	if (fd < 0) {
		errno = EINVAL;
		return -1;
	}

	Context ctx;
	RetSSize ret = { ._errno = errno };
	CallGetXattr call = {
		.type = XATTRTYPE_F,
		.fd = fd,
		.name = name,
		.value = value,
		.size = size,
		.ret = &ret
	};
	_next->getxattr(&ctx, _next->getxattr_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int rename(const char *oldpath, const char *newpath) {

	init();
	trace(": rename(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _rename(oldpath, newpath);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallRename call = {
		.type = RENAMETYPE_PLAIN,
		.oldpath = oldpath,
		.newpath = newpath,
		.ret = &ret
	};
	_next->rename(&ctx, _next->rename_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int renameat(int olddirfd, const char *oldpath,
			 int newdirfd, const char *newpath) {

	init();
	trace(": renameat(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _renameat(olddirfd, oldpath, newdirfd, newpath);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallRename call = {
		.type = RENAMETYPE_AT,
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.ret = &ret
	};
	_next->rename(&ctx, _next->rename_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int renameat2(int olddirfd, const char *oldpath,
			  int newdirfd, const char *newpath, unsigned int flags) {

	init();
	trace(": renameat2(%s, %s)\n", oldpath?oldpath:"NULL", newpath?newpath:"NULL");

	if (!oldpath || !newpath) {
		return _renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallRename call = {
		.type = RENAMETYPE_AT2,
		.olddirfd = olddirfd,
		.oldpath = oldpath,
		.newdirfd = newdirfd,
		.newpath = newpath,
		.flags = flags,
		.ret = &ret
	};
	_next->rename(&ctx, _next->rename_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int scandir(const char *restrict dirp, struct dirent ***restrict namelist,
			int (*filter)(const struct dirent *),
			int (*compar)(const struct dirent **, const struct dirent **)) {

	init();
	trace(": scandir(%s)\n", dirp ? dirp : "NULL");

	if (!dirp) {
		return _scandir(dirp, namelist, filter, compar);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallScandir call = {
		.dirfd = -1,
		.dirp = dirp,
		.namelist = namelist,
		.filter = filter,
		.compar = compar,
		.ret = &ret
	};
	_next->scandir(&ctx, _next->scandir_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

#ifdef _GNU_SOURCE
__attribute__((visibility("default")))
int scandirat(int dirfd, const char *restrict dirp, struct dirent ***restrict namelist,
			  int (*filter)(const struct dirent *),
			  int (*compar)(const struct dirent **, const struct dirent **)) {

	init();
	trace(": scandirat(%s)\n", dirp ? dirp : "NULL");

	if (!dirp) {
		return _scandirat(dirfd, dirp, namelist, filter, compar);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallScandir call = {
		.dirfd = dirfd,
		.dirp = dirp,
		.namelist = namelist,
		.filter = filter,
		.compar = compar,
		.ret = &ret
	};
	_next->scandir(&ctx, _next->scandir_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}
#endif

__attribute__((visibility("default")))
int chdir(const char *path) {

	init();
	trace(": chdir(%s)\n", path ? path : "NULL");

	if (!path) {
		return _chdir(path);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallChdir call = {
		.fd = 0,
		.path = path,
		.ret = &ret
	};
	_next->chdir(&ctx, _next->chdir_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
int fchdir(int fd) {

	init();
	trace(": fchdir(%d)\n", fd);

	if (fd < 0) {
		return _fchdir(fd);
	}

	Context ctx;
	RetInt ret = { ._errno = errno };
	CallChdir call = {
		.fd = fd,
		.ret = &ret
	};
	_next->chdir(&ctx, _next->chdir_next, &call);
	errno = call.ret->_errno;
	return call.ret->ret;
}

__attribute__((visibility("default")))
char *mktemp(char *template) {

	init();
	trace(": mktemp(%s)\n", template ? template : "NULL");

	if (!template) {
		return _mktemp(template);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallMktemp call = {
		.type = MKTEMPTYPE_PLAIN,
		.template = template,
		.ret = &ret
	};
	_next->mktemp(&ctx, _next->mktemp_next, &call);
	errno = ret._errno;
	return ret.ret;
}

__attribute__((visibility("default")))
int mkstemp(char *template) {

	init();
	trace(": mkstemp(%s)\n", template ? template : "NULL");

	if (!template) {
		return _mkstemp(template);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallMktemp call = {
		.type = MKTEMPTYPE_MKS,
		.template = template,
		.ret = &ret
	};
	_next->mktemp(&ctx, _next->mktemp_next, &call);
	errno = ret._errno;
	return ptr_to_int(ret.ret);
}

__attribute__((visibility("default")))
int mkostemp(char *template, int flags) {

	init();
	trace(": mkostemp(%s)\n", template ? template : "NULL");

	if (!template) {
		return _mkostemp(template, flags);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallMktemp call = {
		.type = MKTEMPTYPE_MKOS,
		.template = template,
		.flags = flags,
		.ret = &ret
	};
	_next->mktemp(&ctx, _next->mktemp_next, &call);
	errno = ret._errno;
	return ptr_to_int(ret.ret);
}

__attribute__((visibility("default")))
int mkstemps(char *template, int suffixlen) {

	init();
	trace(": mkstemps(%s)\n", template ? template : "NULL");

	if (!template) {
		return _mkstemps(template, suffixlen);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallMktemp call = {
		.type = MKTEMPTYPE_MKS_S,
		.template = template,
		.suffixlen = suffixlen,
		.ret = &ret
	};
	_next->mktemp(&ctx, _next->mktemp_next, &call);
	errno = ret._errno;
	return ptr_to_int(ret.ret);
}

__attribute__((visibility("default")))
int mkostemps(char *template, int suffixlen, int flags) {

	init();
	trace(": mkostemps(%s)\n", template ? template : "NULL");

	if (!template) {
		return _mkostemps(template, suffixlen, flags);
	}

	Context ctx;
	RetPtr ret = { ._errno = errno };
	CallMktemp call = {
		.type = MKTEMPTYPE_MKOS_S,
		.template = template,
		.suffixlen = suffixlen,
		.flags = flags,
		.ret = &ret
	};
	_next->mktemp(&ctx, _next->mktemp_next, &call);
	errno = ret._errno;
	return ptr_to_int(ret.ret);
}

static int bottom_open(Context *ctx, const This *this,
					   const CallOpen *call) {
	int ret;

	switch (call->type) {
		case OPENTYPE_PLAIN:
			ret = _open(call->path, call->flags, call->mode);
		break;

		case OPENTYPE_2:
			ret = ___open_2(call->path, call->flags);
		break;

		case OPENTYPE_64:
			ret = _open64(call->path, call->flags, call->mode);
		break;

		case OPENTYPE_64_2:
			ret = ___open64_2(call->path, call->flags);
		break;

		case OPENTYPE_AT:
			ret = _openat(call->dirfd, call->path, call->flags, call->mode);
		break;

		case OPENTYPE_AT_2:
			ret = ___openat_2(call->dirfd, call->path, call->flags);
		break;

		case OPENTYPE_AT_64:
			ret = _openat64(call->dirfd, call->path, call->flags, call->mode);
		break;

		case OPENTYPE_AT_64_2:
			ret = ___openat64_2(call->dirfd, call->path, call->flags);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static FILE *bottom_fopen(Context *ctx, const This *this,
						  const CallFOpen *call) {
	FILE *ret;

	if (call->fopen64) {
		ret = _fopen64(call->path, call->mode);
	} else {
		ret = _fopen(call->path, call->mode);
	}

	call->ret->ret = ret;
	if (!ret) {
		call->ret->_errno = errno;
	}

	return ret;
}

static DIR *bottom_opendir(Context *ctx, const This *this,
							const CallOpendir *call) {
	DIR *ret;

	ret = _opendir(call->path);

	call->ret->ret = ret;
	if (!ret) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_stat(Context *ctx, const This *this,
					   const CallStat *call) {
	int ret;

	switch (call->type) {
		case STATTYPE_PLAIN:
			ret = _stat(call->path, call->statbuf);
		break;

		case STATTYPE_64:
			ret = _stat64(call->path, call->statbuf);
		break;

		case STATTYPE___X:
			ret = ___xstat(call->ver, call->path, call->statbuf);
		break;

		case STATTYPE___X_64:
			ret = ___xstat64(call->ver, call->path, call->statbuf);
		break;

		case STATTYPE_L:
			ret = _lstat(call->path, call->statbuf);
		break;

		case STATTYPE_L_64:
			ret = _lstat64(call->path, call->statbuf);
		break;

		case STATTYPE_AT:
			ret = _fstatat(call->dirfd, call->path, call->statbuf, call->flags);
		break;

		case STATTYPE_AT_64:
			ret = _fstatat64(call->dirfd, call->path, call->statbuf, call->flags);
		break;

		case STATTYPE_X:
			ret = _statx(call->dirfd, call->path, call->flags, call->mask,
						 call->statbuf);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static ssize_t bottom_readlink(Context *ctx, const This *this,
							   const CallReadlink *call) {
	ssize_t ret;

	if (call->at) {
		ret = _readlinkat(call->dirfd, call->path, call->buf, call->bufsiz);
	} else {
		ret = _readlink(call->path, call->buf, call->bufsiz);
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_access(Context *ctx, const This *this,
						 const CallAccess *call) {
	int ret;

	switch (call->type) {
		case ACCESSTYPE_PLAIN:
			ret = _access(call->path, call->mode);
		break;

		case ACCESSTYPE_AT:
			ret = _faccessat(call->dirfd, call->path, call->mode, call->flags);
		break;

		case ACCESSTYPE_EUID:
			ret = _euidaccess(call->path, call->mode);
		break;

		case ACCESSTYPE_E:
			ret = _eaccess(call->path, call->mode);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int _bottom_execve(Context *ctx, const This *this,
						  const CallExec *call) {
	int ret;

	switch (call->type) {
		case EXECTYPE_EXECVE:
			ret = _execve(call->path, call->argv, call->envp);
		break;

		case EXECTYPE_EXECVE_AT:
			ret = _execveat(call->dirfd, call->path, call->argv, call->envp,
							call->flags);
		break;

		case EXECTYPE_POSIX_SPAWN:
			ret = _posix_spawn(call->pid, call->path, call->file_actions,
							   call->attrp, call->argv, call->envp);
		break;

		case EXECTYPE_POSIX_SPAWNP:
			ret = _posix_spawnp(call->pid, call->path, call->file_actions,
								call->attrp, call->argv, call->envp);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_exec(Context *ctx, const This *this,
					   const CallExec *call) {
	int fd;
	int _errno = 0;
	ssize_t ret, size;
	int64_t exec_argc;
	CallExec _call;
	callexec_copy(&_call, call);

	if (call->final || (exectype_is_at(call->type) && call->path[0] != '/')) {
		return _bottom_execve(ctx, this, call);
	}

	exec_argc = array_len(call->argv);
	if (exec_argc < 0) {
		call->ret->_errno = E2BIG;
		call->ret->ret = -1;
		goto out;
	}

	ret = _access(call->path, X_OK);
	if (ret < 0) {
		call->ret->_errno = errno;
		call->ret->ret = -1;
		goto out;
	}

	fd = _open(call->path, O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		call->ret->_errno = errno;
		call->ret->ret = -1;
		goto out;
	}

	ret = read_full(fd, ctx->scratch, SCRATCH_SIZE);
	_errno = errno;
	_close(fd);
	if (ret < 0) {
		call->ret->_errno = _errno;
		call->ret->ret = -1;
		goto out;
	}
	size = ret;

	if (size < 2) {
		call->ret->_errno = ENOEXEC;
		call->ret->ret = -1;
		goto out;
	}

	if (ctx->scratch[0] == '#' && ctx->scratch[1] == '!') {
		size = line_size(ctx->scratch, size) + 1;
		char buf[size];
		memcpy(buf, ctx->scratch, size);
		buf[size - 1] = '\0';

		int sh_argc = cmdline_argc(buf, size);
		if (sh_argc == 0) {
			call->ret->_errno = ENOEXEC;
			call->ret->ret = -1;
			goto out;
		}

		int64_t argc = exec_argc + sh_argc;
		char *argv[argc +1];

		cmdline_extract(buf, size, argv);
		array_copy(argv + sh_argc, call->argv, exec_argc);
		argv[sh_argc] = (char *) call->path;
		argv[argc] = NULL;
		const char *pathname = argv[0];

		debug_exec(pathname, argv, call->envp);

		_call.path = pathname;
		_call.argv = argv;

		return _next->exec(ctx, _next->exec_next, &_call);
	}

	_call.final = 1;
	_next->exec(ctx, _next->exec_next, &_call);

out:
	return call->ret->ret;
}

static char *bottom_realpath(Context *ctx, const This *this,
							 const CallRealpath *call) {
	char *ret;

	ret = _realpath(call->path, call->out);

	call->ret->ret = ret;
	if (!ret) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_link(Context *ctx, const This *this,
					   const CallLink *call) {
	int ret;

	if (call->at) {
		ret = _linkat(call->olddirfd, call->oldpath, call->newdirfd,
					  call->newpath, call->flags);
	} else {
		ret = _link(call->oldpath, call->newpath);
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_symlink(Context *ctx, const This *this,
						  const CallLink *call) {
	int ret;

	if (call->at) {
		ret = _symlinkat(call->oldpath, call->newdirfd, call->newpath);
	} else {
		ret = _symlink(call->oldpath, call->newpath);
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_unlink(Context *ctx, const This *this,
						 const CallUnlink *call) {
	int ret;

	if (call->at) {
		ret = _unlinkat(call->dirfd, call->path, call->flags);
	} else {
		ret = _unlink(call->path);
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static ssize_t bottom_listxattr(Context *ctx, const This *this,
								const CallListXattr *call) {
	ssize_t ret;

	switch (call->type) {
		case XATTRTYPE_PLAIN:
			ret = _listxattr(call->path, call->list, call->size);
		break;

		case XATTRTYPE_L:
			ret = _llistxattr(call->path, call->list, call->size);
		break;

		case XATTRTYPE_F:
			ret = _flistxattr(call->fd, call->list, call->size);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_setxattr(Context *ctx, const This *this,
						   const CallSetXattr *call) {
	int ret;

	switch (call->type) {
		case XATTRTYPE_PLAIN:
			ret = _setxattr(call->path, call->name, call->value, call->size,
							call->flags);
		break;

		case XATTRTYPE_L:
			ret = _lsetxattr(call->path, call->name, call->value, call->size,
							 call->flags);
		break;

		case XATTRTYPE_F:
			ret = _fsetxattr(call->fd, call->name, call->value, call->size,
							 call->flags);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static ssize_t bottom_getxattr(Context *ctx, const This *this,
							   const CallGetXattr *call) {
	ssize_t ret;

	switch (call->type) {
		case XATTRTYPE_PLAIN:
			ret = _getxattr(call->path, call->name, call->value, call->size);
		break;

		case XATTRTYPE_L:
			ret = _lgetxattr(call->path, call->name, call->value, call->size);
		break;

		case XATTRTYPE_F:
			ret = _fgetxattr(call->fd, call->name, call->value, call->size);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_rename(Context *ctx, const This *this,
						 const CallRename *call) {
	int ret;

	switch (call->type) {
		case RENAMETYPE_PLAIN:
			ret = _rename(call->oldpath, call->newpath);
		break;

		case RENAMETYPE_AT:
			ret = _renameat(call->olddirfd, call->oldpath,
							call->newdirfd, call->newpath);
		break;

		case RENAMETYPE_AT2:
			ret = _renameat2(call->olddirfd, call->oldpath,
							 call->newdirfd, call->newpath, call->flags);
		break;

		default:
			abort();
		break;
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}

	return ret;
}

static int bottom_scandir(Context *ctx, const This *this,
						  const CallScandir *call) {
	int ret;

	if (call->at) {
		ret = _scandirat(call->dirfd, call->dirp, call->namelist, call->filter,
						 call->compar);
	} else {
		ret = _scandir(call->dirp, call->namelist, call->filter, call->compar);
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}
	return ret;
}

static int bottom_chdir(Context *ctx, const This *this,
						const CallChdir *call) {
	int ret;

	if (call->fd) {
		ret = _fchdir(call->fd);
	} else {
		ret = _chdir(call->path);
	}

	call->ret->ret = ret;
	if (ret < 0) {
		call->ret->_errno = errno;
	}
	return ret;
}

static void *bottom_mktemp(Context *ctx, const This *this,
						   const CallMktemp *call) {
	void *ret_ptr = NULL;
	int ret = -1;

	switch (call->type) {
		case MKTEMPTYPE_PLAIN:
			ret_ptr = _mktemp(call->template);
		break;

		case MKTEMPTYPE_MKS:
			ret = _mkstemp(call->template);
		break;

		case MKTEMPTYPE_MKOS:
			ret = _mkostemp(call->template, call->flags);
		break;

		case MKTEMPTYPE_MKS_S:
			ret = _mkstemps(call->template, call->suffixlen);
		break;

		case MKTEMPTYPE_MKOS_S:
			ret = _mkostemps(call->template, call->suffixlen, call->flags);
		break;

		default:
			abort();
		break;
	}

	if (call->type == MKTEMPTYPE_PLAIN) {
		if (!ret_ptr) {
			call->ret->_errno = errno;
		}
		call->ret->ret = ret_ptr;
		return ret_ptr;
	} else {
		if (ret < 0) {
			call->ret->_errno = errno;
		}
		ret_ptr = int_to_ptr(ret);
		call->ret->ret = ret_ptr;
		return ret_ptr;
	}
}

static const CallHandler bottom = {
	bottom_open,
	NULL,
	bottom_fopen,
	NULL,
	bottom_opendir,
	NULL,
	bottom_stat,
	NULL,
	bottom_readlink,
	NULL,
	bottom_access,
	NULL,
	bottom_exec,
	NULL,
	bottom_realpath,
	NULL,
	bottom_link,
	NULL,
	bottom_symlink,
	NULL,
	bottom_unlink,
	NULL,
	bottom_listxattr,
	NULL,
	bottom_setxattr,
	NULL,
	bottom_getxattr,
	NULL,
	bottom_rename,
	NULL,
	bottom_scandir,
	NULL,
	bottom_chdir,
	NULL,
	bottom_mktemp,
	NULL
};
