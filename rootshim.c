
#include "nolibc.h"

#include "rootshim.h"
#include "config.h"
#include "intercept.h"
#include "mytypes.h"
#include "util.h"

struct This {
	CallHandler this;
	const CallHandler *next;
};

typedef struct Shim Shim;
struct Shim {
	int is_handled;
	int is_symlink;
	char target[];
};

static void shim_unlink(Shim *shim) {
	int ret;

	if (!shim->is_symlink) {
		ret = unlink(shim->target);
		if (ret < 0) {
			abort();
		}
	}
}

void randchar6(char *buf) {
	int ret;
	const char *table = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
	const unsigned int len = strlen(table);
	unsigned char rand[6];

	ret = my_syscall3(__NR_getrandom, rand, 6, 0);
	if (ret < 0) {
		abort();
	}

	for (int i = 0; i < 6; i++) {
		int idx = rand[i] % len;
		buf[i] = table[idx];
	}
}

int mkostemp(char *template, int flags, mode_t mode) {
	int ret;
	size_t len = strlen(template);
	char *xxxxxx = template + len - 6;

	for (int i = 0; i < 6; i++) {
		if (xxxxxx[i] != 'X') {
			abort();
		}
	}

	while (1) {
		randchar6(xxxxxx);
		ret = open(template, flags | O_RDWR | O_CREAT | O_EXCL, mode);
		if (ret < 0) {
			if (ret == EEXIST) {
				continue;
			} else {
				return -1;
			}
		}

		return ret;
	}
}

static ssize_t handle_uptime(Shim *shim, ssize_t shim_len) {
    const char *content = "106315.82 92968.73\n";
	const int content_len = strlen(content);
	char filename[] = PREFIX "/tmp/.rootshim-XXXXXX";
	const ssize_t filename_len = strlen(filename) +1;
	const ssize_t len = sizeof(Shim) + filename_len;
	int ret;
    int fd = 0;

	if (!shim) {
		return len;
	}

	if (shim_len < len) {
		abort();
	}

	ret = mkostemp(filename, 0, 0400);
    if (ret < 0) {
		return -1;
    }
    fd = ret;

    ret = write(fd, content, content_len);
    if (ret < 0) {
        goto fail;
    } else if (ret != content_len) {
        goto fail;
    }

    ret = lseek(fd, SEEK_SET, 0);
    if (ret < 0) {
        goto fail;
    }

	ret = close(fd);
	if (ret < 0) {
		goto fail;
	}

	shim->is_handled = 1;
	shim->is_symlink = 0;
	memcpy(shim->target, filename, filename_len);

	return 0;

fail:
	(void)0;
	int _errno = errno;
	unlink(filename);
	close(fd);
	errno = _errno;
    return -1;
}

static ssize_t handle_exe(Shim *shim, ssize_t shim_len) {
	const ssize_t exe_len = strlen(self_exe) +1;
	const ssize_t len = sizeof(Shim) + exe_len;

	if (!shim) {
		return len;
	}

	if (shim_len < len) {
		abort();
	}

	shim->is_handled = 1;
	shim->is_symlink = 1;
	memcpy(shim->target, self_exe, exe_len);

	return 0;
}

static ssize_t handle_path(Shim *shim, ssize_t shim_len, const char *path) {
	const ssize_t len = sizeof(Shim);

    if (!strcmp(path, "/proc/uptime")) {
		return handle_uptime(shim, shim_len);
	} else if (!strcmp(path, "/proc/self/exe")) {
		return handle_exe(shim, shim_len);
	}

	if (!shim) {
		return len;
	} else {
		if (shim_len < len) {
			abort();
		}
		*shim = (Shim) { .is_handled = 0 };
	}

    return 0;
}

#define _FILL_SHIM(__path, prefix) \
	ssize_t prefix ## shim_ret = handle_path(NULL, 0, (__path)); \
	if (prefix ## shim_ret < 0) { \
		call->ret->_errno = errno; \
		call->ret->ret = -1; \
		return -1; \
	} \
	\
	Shim * prefix ## shim = alloca(prefix ## shim_ret); \
	prefix ## shim_ret = handle_path(prefix ## shim, prefix ## shim_ret, (__path)); \
	if (prefix ## shim_ret < 0) { \
		call->ret->_errno = errno; \
		call->ret->ret = -1; \
		return -1; \
	} \
	(__path) = prefix ## shim->target;

#define FILL_SHIM(__path) \
	_FILL_SHIM(__path, )

static int rootshim_open(Context *ctx, const This *this,
						 const CallOpen *call) {
	RetInt *_ret = call->ret;
	CallOpen _call;
	callopen_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->open(ctx, this->next->open_next, call);
	}

	FILL_SHIM(_call.path);

	if (shim->is_handled) {
		if ((call->flags & O_NOFOLLOW) && shim->is_symlink) {
			_ret->_errno = ELOOP;
			_ret->ret = -1;
			goto fail;
		}

		this->next->open(ctx, this->next->open_next, &_call);
		shim_unlink(shim);

		return _ret->ret;
	} else {
		return this->next->open(ctx, this->next->open_next, call);
	}

fail:
	shim_unlink(shim);
	return _ret->ret;
}

static int rootshim_stat(Context *ctx, const This *this,
						 const CallStat *call) {
	RetInt *_ret = call->ret;
	CallStat _call;
	callstat_copy(&_call, call);

	if ((stattype_is_at(call->type) && call->path[0] != '/') ||
			call->type == STATTYPE_F) {
		return this->next->stat(ctx, this->next->stat_next, call);
	}

	FILL_SHIM(_call.path);

	if (shim->is_handled) {
		// TODO: Do this properly
		if (call->type == STATTYPE_L ||
				(call->type == STATTYPE_X && call->flags & AT_SYMLINK_NOFOLLOW)) {
			shim_unlink(shim);
			return this->next->stat(ctx, this->next->stat_next, call);
		}

		this->next->stat(ctx, this->next->stat_next, &_call);
		shim_unlink(shim);

		return _ret->ret;
	} else {
		return this->next->stat(ctx, this->next->stat_next, call);
	}
}

static ssize_t rootshim_readlink(Context *ctx, const This *this,
								 const CallReadlink *call) {
	RetSSize *_ret = call->ret;
	CallReadlink _call;
	callreadlink_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->readlink(ctx, this->next->readlink_next, call);
	}

	FILL_SHIM(_call.path);

	if (shim->is_handled) {
		size_t len = strlen(shim->target) +1;
		len = min(call->bufsiz, len);

		if (!shim->is_symlink) {
			_ret->_errno = EINVAL;
			_ret->ret = -1;
			goto fail;
		}
		shim_unlink(shim);

		memcpy(call->buf, shim->target, len);

		_ret->ret = len;
		return len;
	} else {
		return this->next->readlink(ctx, this->next->readlink_next, call);
	}

fail:
	shim_unlink(shim);
	return _ret->ret;
}

static int rootshim_access(Context *ctx, const This *this,
						   const CallAccess *call) {
	RetInt *_ret = call->ret;
	CallAccess _call;
	callaccess_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->access(ctx, this->next->access_next, call);
	}

	FILL_SHIM(_call.path);

	if (shim->is_handled) {
		this->next->access(ctx, this->next->access_next, &_call);
		shim_unlink(shim);

		return _ret->ret;
	} else {
		return this->next->access(ctx, this->next->access_next, call);
	}
}

static ssize_t rootshim_xattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	RetSSize *_ret = call->ret;
	CallXattr _call;
	callxattr_copy(&_call, call);

	if (call->type2 == XATTRTYPE_F) {
		return this->next->xattr(ctx, this->next->xattr_next, call);
	}

	FILL_SHIM(_call.path);

	if (shim->is_handled) {
		shim_unlink(shim);
		_ret->_errno = EOPNOTSUPP;
		_ret->ret = -1;
		goto fail;
	} else {
		return this->next->xattr(ctx, this->next->xattr_next, call);
	}

fail:
	shim_unlink(shim);
	return _ret->ret;
}

// Provide only readonly functions for now
// int rootshim_link(Context *ctx, const This *this, CallLink *call);
// int rootshim_symlink(Context *ctx, const This *this, CallLink *call);
// int rootshim_unlink(Context *ctx, const This *this, CallUnlink *call);
// int rootshim_rename(Context *ctx, const This *this, CallRename *call);

const CallHandler *rootshim_init(const CallHandler *next) {
	static int initialized = 0;
	static This this;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this.next = next;
	this.this = *next;

	this.this.open = rootshim_open;
	this.this.open_next = &this;
	this.this.stat = rootshim_stat;
	this.this.stat_next = &this;
	this.this.readlink = rootshim_readlink;
	this.this.readlink_next = &this;
	this.this.access = rootshim_access;
	this.this.access_next = &this;
	this.this.xattr = rootshim_xattr;
	this.this.xattr_next = &this;

	return &this.this;
}
