
#include "nolibc.h"

#include "rootshim.h"
#include "config.h"
#include "intercept.h"
#include "mytypes.h"

struct This {
	CallHandler this;
	const CallHandler *next;
};

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

int mkostemp_unlink(char *template, int flags, mode_t mode) {
	int ret, fd;
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
		fd = ret;

		ret = unlink(template);
		if (ret < 0) {
			int _errno = errno;
			close(fd);
			errno = _errno;
			return -1;
		}

		return fd;
	}
}

static int handle_uptime() {
    const char *content = "106315.82 92968.73\n";
	int content_len = strlen(content);
	char filename[] = PREFIX "/tmp/.rootshim-XXXXXX";
	int ret;
    int fd = 0;

	ret = mkostemp_unlink(filename, 0, 0077);
    if (ret < 0) {
        goto fail;
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

    return fd;

fail:
	close(fd);
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


static int rootshim_open(Context *ctx, const This *this,
						 const CallOpen *call) {
	RetInt *ret = call->ret;

	if (call->at && call->path[0] != '/') {
		return this->next->open(ctx, this->next->open_next, call);
	}

	if (handle_path(call->path, ret)) {
		if (ret->ret < 0) {
			return ret->ret;
		}

		if (call->mode & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) {
			close(ret->ret);
			ret->_errno = EACCES;
			ret->ret = -1;
			return -1;
		}

		return ret->ret;
	}

	return this->next->open(ctx, this->next->open_next, call);
}

static int rootshim_access(Context *ctx, const This *this,
						   const CallAccess *call) {
	RetInt *ret = call->ret;

	if (call->at && call->path[0] != '/') {
		return this->next->access(ctx, this->next->access_next, call);
	}

	if (handle_path(call->path, ret)) {
		if (ret->ret < 0) {
			return ret->ret;
		}
		close(ret->ret);

		if (call->mode != F_OK && (call->mode & (X_OK | W_OK))) {
			ret->_errno = EACCES;
			ret->ret = -1;
			return -1;
		}

		return 0;
	}

	return this->next->access(ctx, this->next->access_next, call);
}

static ssize_t rootshim_xattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	RetInt ret;

	if (call->type2 == XATTRTYPE_F) {
		return this->next->xattr(ctx, this->next->xattr_next, call);
	}

	if (handle_path(call->path, &ret)) {
		if (ret.ret < 0) {
			return ret.ret;
		}
		close(ret.ret);

		call->ret->_errno = EOPNOTSUPP;
		call->ret->ret = -1;
		return -1;
	}

	return this->next->xattr(ctx, this->next->xattr_next, call);
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
	this.this.access = rootshim_access;
	this.this.access_next = &this;
	this.this.xattr = rootshim_xattr;
	this.this.xattr_next = &this;

	return &this.this;
}
