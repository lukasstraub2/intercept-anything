
#include "common.h"

#include "rootshim.h"
#include "config.h"
#include "parent_open.h"
#include "parent_close.h"
#include "parent_link.h"
#include "intercept.h"

#include <sys/stat.h>
#include <errno.h>

struct This {
	CallHandler this;
	const CallHandler *next;
};

static int handle_uptime() {
    const char *content = "106315.82 92968.73\n";
    size_t content_len = strlen(content);
    char *filename = NULL;
    mode_t _umask;
    int _errno, ret;
    int fd = 0;

	filename = strdup(PREFIX "/tmp/.rootshim-XXXXXX");

    _umask = umask(0077);
	ret = mkstemp(filename);
    _errno = errno;
    umask(_umask);

    if (ret < 0) {
        goto fail;
    }
    fd = ret;

	_unlink(filename);
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
    _close(fd);
    free(filename);
    errno = _errno;
    return -1;
}

static int handle_path(const char *path, RetInt *ret) {
    if (!strcmp(path, "/proc/uptime")) {
		ret->ret = handle_uptime();
		if (ret->ret < 0) {
			ret->_errno = errno;
		}
		return 1;
    }

    return 0;
}

static int fhandle_path(const char *path, RetPtr *_ret) {
	RetInt ret;

	if (handle_path(path, &ret)) {
		if (ret.ret < 0) {
			_ret->_errno = ret._errno;
			_ret->ret = NULL;
			return 1;
		}

		_ret->ret = fdopen(ret.ret, "rb");
		if (!_ret->ret) {
			_ret->_errno = errno;
		}
		return 1;
	}

	return 0;
}

static int rootshim_open(Context *ctx, const This *this,
						 const CallOpen *call) {
	RetInt *ret = call->ret;

	if (opentype_is_at(call->type) && call->path[0] != '/') {
		return this->next->open(ctx, this->next->open_next, call);
	}

	if (handle_path(call->path, ret)) {
		if (ret->ret < 0) {
			return ret->ret;
		}

		if (call->mode & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) {
			_close(ret->ret);
			ret->_errno = EACCES;
			ret->ret = -1;
			return -1;
		}

		return ret->ret;
	}

	return this->next->open(ctx, this->next->open_next, call);
}

static FILE *rootshim_fopen(Context *ctx, const This *this,
							const CallFOpen *call) {
	RetPtr *ret = call->ret;

	if (fhandle_path(call->path, ret)) {
		if (!ret->ret) {
			return ret->ret;
		}

		if (!!strcmp(call->mode, "r")) {
			_fclose(ret->ret);
			ret->_errno = EACCES;
			ret->ret = NULL;
			return NULL;
		}

		return ret->ret;
	}

	return this->next->fopen(ctx, this->next->fopen_next, call);
}

static int rootshim_access(Context *ctx, const This *this,
						   const CallAccess *call) {
	RetInt *ret = call->ret;

	if (accesstype_is_at(call->type) && call->path[0] != '/') {
		return this->next->access(ctx, this->next->access_next, call);
	}

	if (handle_path(call->path, ret)) {
		if (ret->ret < 0) {
			return ret->ret;
		}
		_close(ret->ret);

		if (call->mode != F_OK && (call->mode & (X_OK | W_OK))) {
			ret->_errno = EACCES;
			ret->ret = -1;
			return -1;
		}

		return 0;
	}

	return this->next->access(ctx, this->next->access_next, call);
}

static ssize_t rootshim_listxattr(Context *ctx, const This *this,
								  const CallListXattr *call) {
	RetInt ret;

	if (call->type == XATTRTYPE_F) {
		return this->next->listxattr(ctx, this->next->listxattr_next, call);
	}

	if (handle_path(call->path, &ret)) {
		if (ret.ret < 0) {
			return ret.ret;
		}
		_close(ret.ret);

		call->ret->_errno = ENOTSUP;
		call->ret->ret = -1;
		return -1;
	}

	return this->next->listxattr(ctx, this->next->listxattr_next, call);
}

static int rootshim_setxattr(Context *ctx, const This *this,
							 const CallSetXattr *call) {
	RetInt ret;

	if (call->type == XATTRTYPE_F) {
		return this->next->setxattr(ctx, this->next->setxattr_next, call);
	}

	if (handle_path(call->path, &ret)) {
		if (ret.ret < 0) {
			return ret.ret;
		}
		_close(ret.ret);

		call->ret->_errno = ENOTSUP;
		call->ret->ret = -1;
		return -1;
	}

	return this->next->setxattr(ctx, this->next->setxattr_next, call);
}

static ssize_t rootshim_getxattr(Context *ctx, const This *this,
								 const CallGetXattr *call) {
	RetInt ret;

	if (call->type == XATTRTYPE_F) {
		return this->next->getxattr(ctx, this->next->getxattr_next, call);
	}

	if (handle_path(call->path, &ret)) {
		if (ret.ret < 0) {
			return ret.ret;
		}
		_close(ret.ret);

		call->ret->_errno = ENOTSUP;
		call->ret->ret = -1;
		return -1;
	}

	return this->next->getxattr(ctx, this->next->getxattr_next, call);
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
	this.this.fopen = rootshim_fopen;
	this.this.fopen_next = &this;
	this.this.access = rootshim_access;
	this.this.access_next = &this;
	this.this.listxattr = rootshim_listxattr;
	this.this.listxattr_next = &this;
	this.this.setxattr = rootshim_setxattr;
	this.this.setxattr_next = &this;
	this.this.getxattr = rootshim_getxattr;
	this.this.getxattr_next = &this;

	return &this.this;
}