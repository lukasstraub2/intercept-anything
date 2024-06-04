
#include "common.h"

#define DEBUG_ENV "HARDLINK_DEBUG"
#include "debug.h"
#include "config.h"
#include "util.h"

#include "hardlinkshim.h"
#include "parent_close.h"
#include "parent_link.h"
#include "parent_open.h"
#include "parent_stat.h"
#include "intercept.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

struct This {
	CallHandler this;
	const CallHandler *next;
	int dirfd;
};

#define HARDLINK_PREFIX PREFIX "/tmp/hardlinkshim/"
#define LOCKFILE "lock"

static int lock(const This *this, int operation) {
	int ret, fd;

	ret = _openat64(this->dirfd, LOCKFILE, O_RDWR | O_CLOEXEC, 0777);
	if (ret < 0) {
		return ret;
	}
	fd = ret;

	while (1) {
		ret = flock(fd, operation);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}

			_close(fd);
			return -1;
		}

		break;
	}

	return fd;
}

static int unlock(int fd) {
	int ret, errno_bak;

	ret = flock(fd, LOCK_UN);
	errno_bak = errno;
	_close(fd);
	if (ret < 0) {
		errno = errno_bak;
		return -1;
	}

	return 0;
}

static int changeprefix(char *linkname, const char *newprefix) {
	char *file;
	size_t len, prefix_len;

	prefix_len = strlen(newprefix);
	file = strrchr(linkname, '/');
	if (!file) {
		errno = EINVAL;
		return -1;
	}
	file++;

	len = strlen(file);
	if (len < prefix_len +1) {
		errno = EINVAL;
		return -1;
	}

	memcpy(file, newprefix, prefix_len);
	return 0;
}

static int cnt_read(char *linkname) {
	ssize_t ret;
	char buf[SCRATCH_SIZE];
	int cnt;

	ret = changeprefix(linkname, "cnt");
	if (ret < 0) {
		return -1;
	}

	ret = _readlink(linkname, buf, SCRATCH_SIZE);
	if (ret < 0) {
		goto err;
	} else if (ret == SCRATCH_SIZE) {
		errno = ENAMETOOLONG;
		goto err;
	}
	buf[ret] = '\0';

	cnt = atoi(buf);
	if (cnt < 0) {
		errno = EUCLEAN;
		goto err;
	}

	changeprefix(linkname, "ino");
	return cnt;

err:
	changeprefix(linkname, "ino");
	return -1;
}

static int cnt_write(char *linkname, int cnt) {
	int tmp;
	ssize_t ret;
	size_t len = strlen(linkname) +1;
	char buf[SCRATCH_SIZE];
	char tmpname[len];
	memcpy(tmpname, linkname, len);

	ret = changeprefix(linkname, "cnt");
	if (ret < 0) {
		return -1;
	}
	changeprefix(tmpname, "tmp");

	snprintf(buf, SCRATCH_SIZE, "%d", cnt);

	_unlink(tmpname);
	ret = _symlink(buf, tmpname);
	if (ret < 0) {
		goto err;
	}

	ret = _rename(tmpname, linkname);
	if (ret < 0) {
		goto err;
	}

	changeprefix(linkname, "ino");
	return cnt;

err:
	tmp = errno;
	changeprefix(linkname, "ino");
	_unlink(tmpname);
	errno = tmp;
	return -1;
}

static int cnt_add(char *linkname, int add) {
	int ret;

	ret = cnt_read(linkname);
	if (ret < 0) {
		if (errno == ENOENT) {
			ret = 0;
		} else {
			return -1;
		}
	}

	ret = cnt_write(linkname, ret + add);
	if (ret < 0) {
		return -1;
	}

	return ret;
}

static ssize_t readlink_scratch(Context *ctx, int dirfd, const char *path) {
	ssize_t ret;

	ret = _readlinkat(dirfd, path, ctx->scratch, SCRATCH_SIZE);
	if (ret < 0) {
		return -1;
	} else if (ret == SCRATCH_SIZE) {
		errno = ENAMETOOLONG;
		return -1;
	}
	ctx->scratch[ret] = '\0';

	return ret +1;
}

static int is_hardlinkat(Context *ctx, int dirfd, const char *path) {
	ssize_t ret;

	ret = readlink_scratch(ctx, dirfd, path);
	if (ret < 0) {
		if (errno == EINVAL) {
			return 0;
		} else {
			return -1;
		}
	}

	if (!strcmp_prefix(ctx->scratch, HARDLINK_PREFIX)) {
		return 1;
	}

	return 0;
}

static int _copy_symlink(Context *ctx, int olddirfd, const char *oldpath,
						 int newdirfd, const char *newpath) {
	ssize_t ret;

	ret = readlink_scratch(ctx, olddirfd, oldpath);
	if (ret < 0) {
		return -1;
	}

	ret = _symlinkat(ctx->scratch, newdirfd, newpath);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int copy_symlink(Context *ctx, const CallLink *call) {
	if (call->at) {
		return _copy_symlink(ctx, call->olddirfd, call->oldpath,
							 call->newdirfd, call->newpath);
	} else {
		return _copy_symlink(ctx, AT_FDCWD, call->oldpath, AT_FDCWD,
							 call->newpath);
	}
}

static int _add_hardlink(Context *ctx, int olddirfd, const char *oldpath,
						 int newdirfd, const char *newpath) {
	ssize_t ret;

	ret = readlink_scratch(ctx, olddirfd, oldpath);
	if (ret < 0) {
		return -1;
	}

	ret = _symlinkat(ctx->scratch, newdirfd, newpath);
	if (ret < 0) {
		return -1;
	}

	ret = cnt_add(ctx->scratch, 1);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int add_hardlink(Context *ctx, const CallLink *call) {
	if (call->at) {
		return _add_hardlink(ctx, call->olddirfd, call->oldpath,
							 call->newdirfd, call->newpath);
	} else {
		return _add_hardlink(ctx, AT_FDCWD, call->oldpath, AT_FDCWD,
							 call->newpath);
	}
}

static int del_hardlink(Context *ctx, int dirfd, const char *path) {
	ssize_t ret;

	ret = readlink_scratch(ctx, dirfd, path);
	if (ret < 0) {
		return -1;
	}

	ret = _unlinkat(dirfd, path, 0);
	if (ret < 0) {
		return -1;
	}

	ret = cnt_add(ctx->scratch, -1);
	if (ret < 0) {
		return -1;
	}

	if (ret) {
		return 0;
	}

	ret = _unlink(ctx->scratch);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int hardlink_stat(Context *ctx, const This *this,
						 const CallStat *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	ret = lock(this, LOCK_SH);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	ret = is_hardlinkat(ctx, (stattype_is_at(call->type)? call->dirfd: AT_FDCWD),
						call->path);
	if (ret < 0) {
		goto err;
	}

	if (ret) {
		int cnt;
		struct stat *statbuf_plain;
		struct stat64 *statbuf_64;
		struct statx *statbuf_x;
		CallStat _call;
		callstat_copy(&_call, call);

		ret = readlink_scratch(ctx,
							   (stattype_is_at(call->type)? call->dirfd: AT_FDCWD),
							   call->path);
		if (ret < 0) {
			goto err;
		}

		ret = cnt_read(ctx->scratch);
		if (ret < 0) {
			goto err;
		}
		cnt = ret;

		if (call->type == STATTYPE_L) {
			_call.type = STATTYPE_PLAIN;
		} else if (call->type == STATTYPE_L_64) {
			_call.type = STATTYPE_64;
		} else if (stattype_is_at(call->type)) {
			_call.flags &= ~AT_SYMLINK_NOFOLLOW;
		}

		ret = this->next->stat(ctx, this->next->stat_next, &_call);
		if (ret < 0) {
			unlock(lock_fd);
			return -1;
		}

		switch (_call.type) {
			case STATTYPE_PLAIN:
			case STATTYPE___X:
			case STATTYPE_L:
			case STATTYPE_AT:
				statbuf_plain = _call.statbuf;
				statbuf_plain->st_nlink = cnt;
			break;

			case STATTYPE_64:
			case STATTYPE___X_64:
			case STATTYPE_L_64:
			case STATTYPE_AT_64:
				statbuf_64 = _call.statbuf;
				statbuf_64->st_nlink = cnt;
			break;

			case STATTYPE_X:
				statbuf_x = _call.statbuf;
				statbuf_x->stx_nlink = cnt;
			break;
		}
	} else {
		this->next->stat(ctx, this->next->stat_next, call);
	}

	ret = unlock(lock_fd);
	if (ret < 0) {
		goto err;
	}
	return _ret->ret;

err:
	_ret->_errno = errno;
	unlock(lock_fd);
	_ret->ret = -1;
	return -1;
}

static int hardlink_link(Context *ctx, const This *this,
						 const CallLink *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	if (call->at && call->flags & (AT_EMPTY_PATH | AT_SYMLINK_FOLLOW)) {
		// TODO: Handle AT_SYMLINK_FOLLOW
		_ret->_errno = ENOENT;
		_ret->ret = -1;
		return -1;
	}

	ret = lock(this, LOCK_EX);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	ret = is_hardlinkat(ctx, (call->at? call->olddirfd: AT_FDCWD),
						call->oldpath);
	if (ret < 0) {
		goto err;
	}

	if (ret) {
		ret = add_hardlink(ctx, call);
		if (ret < 0) {
			goto err;
		}
	} else {
		struct stat64 statbuf;
		ret = _fstatat64((call->at? call->olddirfd: AT_FDCWD), call->oldpath,
						 &statbuf, AT_SYMLINK_NOFOLLOW);
		if (ret < 0) {
			goto err;
		}

		if ((statbuf.st_mode & S_IFMT) == S_IFLNK) {
			ret = copy_symlink(ctx, call);
			if (ret < 0) {
				goto err;
			}
		} else if ((statbuf.st_mode & S_IFMT) == S_IFREG) {
			size_t len;
			len = snprintf(NULL, 0, "ino_%lu", statbuf.st_ino) +1;
			char file[len];
			snprintf(file, len, "ino_%lu", statbuf.st_ino);

			len = concat(NULL, 0, HARDLINK_PREFIX, file);
			char linkname[len];
			concat(linkname, len, HARDLINK_PREFIX, file);

			ret = _access(linkname, F_OK);
			if (ret == 0) {
				errno = EUCLEAN;
				goto err;
			}

			ret = _renameat((call->at? call->olddirfd: AT_FDCWD), call->oldpath,
							AT_FDCWD, linkname);
			if (ret < 0) {
				goto err;
			}

			ret = _symlinkat(linkname, (call->at? call->olddirfd: AT_FDCWD),
							 call->oldpath);
			if (ret < 0) {
				goto err;
			}

			ret = cnt_add(linkname, 1);
			if (ret < 0) {
				goto err;
			}

			ret = _symlinkat(linkname, (call->at? call->newdirfd: AT_FDCWD),
							 call->newpath);
			if (ret < 0) {
				goto err;
			}

			ret = cnt_add(linkname, 1);
			if (ret < 0) {
				goto err;
			}
		} else {
			errno = EINVAL;
			goto err;
		}
	}

	ret = unlock(lock_fd);
	if (ret < 0) {
		goto err;
	}
	return 0;

err:
	_ret->_errno = errno;
	unlock(lock_fd);
	_ret->ret = -1;
	return -1;
}

static int hardlink_unlink(Context *ctx, const This *this,
						   const CallUnlink *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	ret = lock(this, LOCK_EX);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	ret = is_hardlinkat(ctx, (call->at? call->dirfd: AT_FDCWD), call->path);
	if (ret < 0) {
		goto err;
	}

	if (ret) {
		ret = del_hardlink(ctx, (call->at? call->dirfd: AT_FDCWD), call->path);
		if (ret < 0) {
			goto err;
		}
	} else {
		this->next->unlink(ctx, this->next->unlink_next, call);
	}

	ret = unlock(lock_fd);
	if (ret < 0) {
		goto err;
	}
	return _ret->ret;

err:
	_ret->_errno = errno;
	unlock(lock_fd);
	_ret->ret = -1;
	return -1;
}

static int mkpath(const char *_file_path, mode_t mode) {
	char *path;
	size_t len = strlen(_file_path) +1;
	char file_path[len];
	memcpy(file_path, _file_path, len);

	for (path = strchr(file_path + 1, '/'); path; path = strchr(path + 1, '/')) {
		*path = '\0';
		if (mkdir(file_path, mode) == -1) {
			if (errno != EEXIST) {
				*path = '/';
				return -1;
			}
		}
		*path = '/';
	}

	return 0;
}

const CallHandler *hardlinkshim_init(const CallHandler *next) {
	static This this;
	static int initialized = 0;
	int ret;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this.next = next;
	this.this = *next;

	this.this.stat = hardlink_stat;
	this.this.stat_next = &this;
	this.this.link = hardlink_link;
	this.this.link_next = &this;
	this.this.unlink = hardlink_unlink;
	this.this.unlink_next = &this;

	ret = mkpath(HARDLINK_PREFIX LOCKFILE, 0777);
	if (ret < 0) {
		debug(DEBUG_LEVEL_ALWAYS, __FILE__": mkpath(%s): %s\n", LOCKFILE,
			  strerror(errno));
		return NULL;
	}

	ret = _open64(HARDLINK_PREFIX LOCKFILE, O_CREAT | O_RDWR, 0777);
	if (ret < 0) {
		debug(DEBUG_LEVEL_ALWAYS, __FILE__": open64(%s): %s\n",
			  HARDLINK_PREFIX LOCKFILE,
			  strerror(errno));
		return NULL;
	}
	_close(ret);

	ret = _open64(HARDLINK_PREFIX, O_DIRECTORY | O_RDONLY | O_CLOEXEC, 0777);
	if (ret < 0) {
		debug(DEBUG_LEVEL_ALWAYS, __FILE__": open64(%s): %s\n", HARDLINK_PREFIX,
			  strerror(errno));
		return NULL;
	}
	this.dirfd = ret;

	return &this.this;
}
