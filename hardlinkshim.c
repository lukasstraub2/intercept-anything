
#define DEBUG_ENV "HARDLINK_DEBUG"
#include "debug.h"
#include "config.h"
#include "util.h"

#include "hardlinkshim.h"
#include "intercept.h"

#include "nolibc.h"
#include "mysys.h"
#include "mytypes.h"

#define stat wonky_stat
#include "asm/stat.h"
#undef stat

struct This {
	CallHandler this;
	const CallHandler *next;
	const CallHandler *bottom;
	dev_t prefix_dev;
	ino_t prefix_ino;
};

#define HARDLINK_PREFIX PREFIX "/tmp/hardlinkshim/"
#define LOCKFILE "lock"

static int lock(const This *this, int operation) {
	int ret, fd;

	ret = open(HARDLINK_PREFIX LOCKFILE, O_RDWR | O_CLOEXEC, 0777);
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

			close(fd);
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
	close(fd);
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

	ret = readlink(linkname, buf, SCRATCH_SIZE);
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
	char cnt_buf[21];
	char tmpname[len];
	memcpy(tmpname, linkname, len);

	ret = changeprefix(linkname, "cnt");
	if (ret < 0) {
		return -1;
	}
	changeprefix(tmpname, "tmp");

	itoa_r(cnt, cnt_buf);

	unlink(tmpname);
	ret = symlink(cnt_buf, tmpname);
	if (ret < 0) {
		goto err;
	}

	ret = rename(tmpname, linkname);
	if (ret < 0) {
		goto err;
	}

	changeprefix(linkname, "ino");
	return cnt;

err:
	tmp = errno;
	changeprefix(linkname, "ino");
	unlink(tmpname);
	errno = tmp;
	return -1;
}

static int cnt_del(char *linkname) {
	int ret;

	ret = changeprefix(linkname, "cnt");
	if (ret < 0) {
		return -1;
	}

	ret = unlink(linkname);
	changeprefix(linkname, "ino");
	if (ret < 0) {
		return -1;
	}

	return 0;
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

	ret = readlinkat(dirfd, path, ctx->scratch, SCRATCH_SIZE);
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
		if (errno == EINVAL || errno == ENOENT) {
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

static int _is_inside_prefix(const This *this, const char *component) {
	struct stat statbuf;
	int ret;

	ret = stat(component, &statbuf);
	if (ret < 0) {
		return -1;
	}

	if (statbuf.st_dev == this->prefix_dev &&
			statbuf.st_ino == this->prefix_ino) {
		return 1;
	}

	return 0;
}

static int is_dotdot(const char *path) {
	char *last = strrchr(path, '/') +1;

	return last[0] == '.' && last[1] == '.' && last[2] == '\0';
}

static int is_empty(const char *path) {
	char *last = strrchr(path, '/') +1;

	return last[0] == '\0' || (last[0] == '.' && last[1] == '\0');
}

static int is_inside_prefix(const This *this, const char *_file_path) {
	int ret;
	int inside = 0;
	char *path;
	size_t len = strlen(_file_path) +1;
	char file_path[len];
	memcpy(file_path, _file_path, len);

	for (path = file_path + len - 2; path >= file_path && *path == '/'; path--) {
		*path = '\0';
	}

	// Skip the first few components that may match our prefix
	// This reduces the number of stat calls we do later
	int components = -2;
	for (path = strchr(PREFIX, '/'); path; path = strchr(path + 1, '/')) {
		components++;
	}

	for (path = strchr(file_path + 1, '/'); path; path = strchr(path + 1, '/')) {
		if (components-- >= 0) {
			continue;
		}
		*path = '\0';

		if (inside) {
			if (is_dotdot(file_path)) {
				inside--;
			} else if (!is_empty(file_path)) {
				inside++;
			}
		} else {
			ret = _is_inside_prefix(this, file_path);
			if (ret < 0) {
				if (errno == EACCES || errno == ENOENT) {
					return 0;
				} else {
					return -1;
				}
			}
			if (ret) {
				inside++;
			}
		}

		*path = '/';
	}

	return inside;
}

// Only use this for rename and link
static int is_inside_prefixat(Context *ctx, const This *this, int dirfd,
							  const char *path) {
	int ret;
	char dirfd_buf[21];
	char buf[SCRATCH_SIZE];

	if (path[0] == '/') {
		return is_inside_prefix(this, path);
	}

	const char *prefix = "/proc/self/fd/";
	itoa_r(dirfd, dirfd_buf);
	ret = concat(buf, SCRATCH_SIZE, prefix, dirfd_buf);
	if (ret >= SCRATCH_SIZE) {
		errno = ENAMETOOLONG;
		return -1;
	}

	if (dirfd == AT_FDCWD) {
		ret = getcwd(ctx->scratch, SCRATCH_SIZE);
	} else {
		ret = readlink_scratch(ctx, AT_FDCWD, buf);
	}
	if (ret < 0) {
		if (errno == ENOENT) {
			errno = EBADF;
		}
		return -1;
	}

	size_t len = strlen(ctx->scratch) +1;
	if (len +1 >= SCRATCH_SIZE) {
		errno = ENAMETOOLONG;
		return -1;
	}
	ctx->scratch[len -1] = '/';
	ctx->scratch[len] = '\0';

	ret = concat(buf, SCRATCH_SIZE, ctx->scratch, path);
	if (ret >= SCRATCH_SIZE) {
		errno = ENAMETOOLONG;
		return -1;
	}

	return is_inside_prefix(this, buf);
}

static int ab_inside_prefixat(Context *ctx, const This *this,
							  int dirfda, const char *patha,
							  int dirfdb, const char *pathb) {
	int ret, a_inprefix, b_inprefix;

	ret = is_inside_prefixat(ctx, this, dirfda, patha);
	if (ret < 0) {
		return -1;
	}
	a_inprefix = ret;

	ret = is_inside_prefixat(ctx, this, dirfdb, pathb);
	if (ret < 0) {
		return -1;
	}
	b_inprefix = ret;

	if (!a_inprefix || !b_inprefix) {
		if (a_inprefix == b_inprefix) {
			errno = EOPNOTSUPP;
			return -1;
		} else {
			errno = EXDEV;
			return -1;
		}
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

	ret = symlinkat(ctx->scratch, newdirfd, newpath);
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

	ret = symlinkat(ctx->scratch, newdirfd, newpath);
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

static int del_hardlink(char *linkname) {
	int ret;

	ret = cnt_add(linkname, -1);
	if (ret < 0) {
		return -1;
	}

	if (ret) {
		return 0;
	}

	ret = unlink(linkname);
	if (ret < 0) {
		return -1;
	}

	ret = cnt_del(linkname);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int hardlink_open(Context *ctx, const This *this,
						 const CallOpen *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	ret = lock(this, LOCK_SH);
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
		CallOpen _call;
		callopen_copy(&_call, call);

		_call.flags &= ~(O_NOFOLLOW);
		this->next->open(ctx, this->next->open_next, &_call);
	} else {
		this->next->open(ctx, this->next->open_next, call);
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

	if (call->type == STATTYPE_F) {
		ret = 0;
	} else {
		ret = is_hardlinkat(ctx, (stattype_is_at(call->type)? call->dirfd: AT_FDCWD),
							call->path);
	}
	if (ret < 0) {
		goto err;
	}

	if (ret) {
		int cnt;
		struct wonky_stat *statbuf_plain;
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
			case STATTYPE_L:
			case STATTYPE_AT:
				statbuf_plain = _call.statbuf;
				statbuf_plain->st_nlink = cnt;
			break;

			case STATTYPE_X:
				statbuf_x = _call.statbuf;
				statbuf_x->stx_nlink = cnt;
			break;

			default:
				abort();
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

static ssize_t hardlink_readlink(Context *ctx, const This *this,
								 const CallReadlink *call) {
	int ret, lock_fd;
	RetSSize *_ret = call->ret;

	ret = lock(this, LOCK_SH);
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
		_ret->_errno = EINVAL;
		_ret->ret = -1;
	} else {
		this->next->readlink(ctx, this->next->readlink_next, call);
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

static int hardlink_access(Context *ctx, const This *this,
						   const CallAccess *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	ret = lock(this, LOCK_SH);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	this->next->access(ctx, this->next->access_next, call);

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

static int hardlink_exec(Context *ctx, const This *this, const CallExec *call) {
	int ret;
	RetInt *_ret = call->ret;

	// Do not take lock since exec may recurse
	ret = is_hardlinkat(ctx, (call->at? call->dirfd: AT_FDCWD), call->path);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}

	if (ret) {
		CallExec _call;
		callexec_copy(&_call, call);

		if (call->at) {
			_call.flags &= ~AT_SYMLINK_NOFOLLOW;
		}

		this->next->exec(ctx, this->next->exec_next, &_call);
	} else {
		this->next->exec(ctx, this->next->exec_next, call);
	}

	return _ret->ret;
}

static int hardlink_link(Context *ctx, const This *this,
						 const CallLink *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	if (call->at) {
		ret = ab_inside_prefixat(ctx, this, call->olddirfd, call->oldpath,
								 call->newdirfd, call->newpath);
	} else {
		ret = ab_inside_prefixat(ctx, this, AT_FDCWD, call->oldpath,
								 AT_FDCWD, call->newpath);
	}
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}

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
		struct statx statbuf;
		ret = __sysret(sys_statx((call->at? call->olddirfd: AT_FDCWD),
								 call->oldpath,
								 AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
								 STATX_TYPE | STATX_MODE | STATX_INO,
								 &statbuf));
		if (ret < 0) {
			goto err;
		}

		if ((statbuf.stx_mode & S_IFMT) == S_IFLNK) {
			ret = copy_symlink(ctx, call);
			if (ret < 0) {
				goto err;
			}
		} else if ((statbuf.stx_mode & S_IFMT) == S_IFREG) {
			size_t len;
			char ino_buf[21];
			const char *prefix = "ino_";
			u64toa_r(statbuf.stx_ino, ino_buf);
			len = strlen(prefix) + 21;
			char file[len];
			concat(file, len, prefix, ino_buf);

			len = concat(NULL, 0, HARDLINK_PREFIX, file);
			char linkname[len];
			concat(linkname, len, HARDLINK_PREFIX, file);

			ret = access(linkname, F_OK);
			if (ret == 0) {
				errno = EUCLEAN;
				goto err;
			}

			ret = renameat((call->at? call->olddirfd: AT_FDCWD), call->oldpath,
						   AT_FDCWD, linkname);
			if (ret < 0) {
				goto err;
			}

			ret = symlinkat(linkname, (call->at? call->olddirfd: AT_FDCWD),
							call->oldpath);
			if (ret < 0) {
				goto err;
			}

			ret = cnt_add(linkname, 1);
			if (ret < 0) {
				goto err;
			}

			ret = symlinkat(linkname, (call->at? call->newdirfd: AT_FDCWD),
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

static int hardlink_symlink(Context *ctx, const This *this,
							const CallLink *call) {
	int ret, lock_fd;
	RetInt *_ret = call->ret;

	ret = lock(this, LOCK_SH);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	this->next->symlink(ctx, this->next->symlink_next, call);

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

static int hardlink_unlink(Context *ctx, const This *this,
						   const CallUnlink *call) {
	ssize_t ret;
	int lock_fd;
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
		ret = readlink_scratch(ctx, (call->at? call->dirfd: AT_FDCWD),
							   call->path);
		if (ret < 0) {
			goto err;
		}

		ret = this->bottom->unlink(ctx, NULL, call);
		if (ret < 0) {
			goto err;
		}

		ret = del_hardlink(ctx->scratch);
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

static ssize_t hardlink_xattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	int ret, lock_fd;
	RetSSize *_ret = call->ret;

	ret = lock(this, LOCK_SH);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	if (call->type2 == XATTRTYPE_F) {
		ret = 0;
	} else {
		ret = is_hardlinkat(ctx, AT_FDCWD, call->path);
		if (ret < 0) {
			goto err;
		}
	}

	if (ret) {
		CallXattr _call;
		callxattr_copy(&_call, call);

		if (call->type2 == XATTRTYPE_L) {
			_call.type2 = XATTRTYPE_PLAIN;
		}

		this->next->xattr(ctx, this->next->xattr_next, &_call);
	} else {
		this->next->xattr(ctx, this->next->xattr_next, call);
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

static int hardlink_rename(Context *ctx, const This *this,
						   const CallRename *call) {
	ssize_t ret;
	int lock_fd;
	RetInt *_ret = call->ret;

	if (renametype_is_at(call->type)) {
		ret = ab_inside_prefixat(ctx, this, call->olddirfd, call->oldpath,
								 call->newdirfd, call->newpath);
	} else {
		ret = ab_inside_prefixat(ctx, this, AT_FDCWD, call->oldpath,
								 AT_FDCWD, call->newpath);
	}
	if (ret < 0) {
		if (errno != EOPNOTSUPP) {
			_ret->_errno = errno;
			_ret->ret = -1;
			return -1;
		}
	}

	ret = lock(this, LOCK_EX);
	if (ret < 0) {
		_ret->_errno = errno;
		_ret->ret = -1;
		return -1;
	}
	lock_fd = ret;

	if (call->type == RENAMETYPE_AT2 &&
			call->flags & (RENAME_EXCHANGE | RENAME_NOREPLACE)) {
		ret = 0;
	} else {
		ret = is_hardlinkat(ctx, (renametype_is_at(call->type)?
									  call->newdirfd: AT_FDCWD),
							call->newpath);
		if (ret < 0) {
			goto err;
		}
	}

	if (ret) {
		ret = readlink_scratch(ctx, (renametype_is_at(call->type)?
										 call->newdirfd: AT_FDCWD),
							   call->newpath);
		if (ret < 0) {
			goto err;
		}

		ret = this->bottom->rename(ctx, NULL, call);
		if (ret < 0) {
			goto err;
		}

		ret = del_hardlink(ctx->scratch);
		if (ret < 0) {
			goto err;
		}
	} else {
		this->next->rename(ctx, this->next->rename_next, call);
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

const CallHandler *hardlinkshim_init(const CallHandler *next,
									 const CallHandler *bottom) {
	static This this;
	static int initialized = 0;
	struct stat statbuf;
	int ret;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this.next = next;
	this.bottom = bottom;
	this.this = *next;

	this.this.open = hardlink_open;
	this.this.open_next = &this;
	this.this.stat = hardlink_stat;
	this.this.stat_next = &this;
	this.this.readlink = hardlink_readlink;
	this.this.readlink_next = &this;
	this.this.access = hardlink_access;
	this.this.access_next = &this;
	this.this.exec = hardlink_exec;
	this.this.exec_next = &this;
	this.this.link = hardlink_link;
	this.this.link_next = &this;
	this.this.symlink = hardlink_symlink;
	this.this.symlink_next = &this;
	this.this.unlink = hardlink_unlink;
	this.this.unlink_next = &this;
	this.this.xattr = hardlink_xattr;
	this.this.xattr_next = &this;
	this.this.rename = hardlink_rename;
	this.this.rename_next = &this;

	ret = mkpath(HARDLINK_PREFIX LOCKFILE, 0777);
	if (ret < 0) {
		exit_error("mkpath(%s): %d", LOCKFILE, errno);
		return NULL;
	}

	ret = open(HARDLINK_PREFIX LOCKFILE, O_CREAT | O_RDWR, 0777);
	if (ret < 0) {
		exit_error("open64(%s): %d", HARDLINK_PREFIX LOCKFILE, errno);
		return NULL;
	}
	close(ret);

	ret = stat(PREFIX, &statbuf);
	if (ret < 0) {
		exit_error("stat64(%s): %d", PREFIX, errno);
		return NULL;
	}
	this.prefix_dev = statbuf.st_dev;
	this.prefix_ino = statbuf.st_ino;

	return &this.this;
}
