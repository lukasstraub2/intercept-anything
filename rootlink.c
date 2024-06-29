
#include "rootlink.h"
#include "config.h"
#include "intercept.h"
#include "util.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>

struct This {
	CallHandler this;
	const CallHandler *next;
};

static int handle_path(const char *path) {
	return !strcmp_prefix(path, "/usr") ||
			!strcmp_prefix(path, "/bin") ||
			!strcmp_prefix(path, "/dev/shm") ||
			!strcmp_prefix(path, "/tmp");
}

static ssize_t mangle_path(char *out, size_t out_len, const char *path) {
    size_t len;

	if (!handle_path(path)) {
		len = strlen(path) +1;
		if (!out) {
			return len;
		}

		if (len > out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
		memcpy(out, path, len);
		return len;
    }

    len = concat(out, out_len, PREFIX "/tmp/rootlink", path);
	if (!out) {
		return len;
	}

    if (len > out_len) {
        errno = ENAMETOOLONG;
        return -1;
    }

	return len;
}

#define _MANGLE_PATH(__path, errret, prefix) \
	ssize_t prefix ## len = mangle_path(NULL, 0, (__path)); \
	if (prefix ## len > SCRATCH_SIZE) { \
		call->ret->_errno = ENAMETOOLONG; \
		call->ret->ret = (errret); \
		return (errret); \
	} \
	\
	char prefix ## buf[prefix ## len]; \
	prefix ## len = mangle_path(prefix ## buf, prefix ## len, (__path)); \
	assert(prefix ## len >= 0); \
	(__path) = prefix ## buf

#define MANGLE_PATH(__path, errret) \
	_MANGLE_PATH(__path, errret, )

static int rootlink_open(Context *ctx, const This *this,
						 const CallOpen *call) {
	CallOpen _call;
	callopen_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->open(ctx, this->next->open_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->open(ctx, this->next->open_next, &_call);
}

static int rootlink_stat(Context *ctx, const This *this,
						 const CallStat *call) {
	CallStat _call;
	callstat_copy(&_call, call);

	if ((stattype_is_at(call->type) && call->path[0] != '/') ||
			call->type == STATTYPE_F) {
		return this->next->stat(ctx, this->next->stat_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->stat(ctx, this->next->stat_next, &_call);
}

static ssize_t rootlink_readlink(Context *ctx, const This *this,
								 const CallReadlink *call) {
	CallReadlink _call;
	callreadlink_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->readlink(ctx, this->next->readlink_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->readlink(ctx, this->next->readlink_next, &_call);
}

static int rootlink_access(Context *ctx, const This *this,
						   const CallAccess *call) {
	CallAccess _call;
	callaccess_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->access(ctx, this->next->access_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->access(ctx, this->next->access_next, &_call);
}

static int rootlink_exec(Context *ctx, const This *this,
						 const CallExec *call) {
	CallExec _call;
	callexec_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->exec(ctx, this->next->exec_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->exec(ctx, this->next->exec_next, &_call);
}

static int rootlink_link(Context *ctx, const This *this,
						 const CallLink *call) {
	CallLink _call;
	calllink_copy(&_call, call);

	_MANGLE_PATH(_call.oldpath, -1, old);
	_MANGLE_PATH(_call.newpath, -1, new);

	if (call->at && call->oldpath[0] != '/') {
		_call.oldpath = call->oldpath;
	}

	if (call->at && call->newpath[0] != '/') {
		_call.newpath = call->newpath;
	}

	return this->next->link(ctx, this->next->link_next, &_call);
}

static int rootlink_symlink(Context *ctx, const This *this,
							const CallLink *call) {
	CallLink _call;
	calllink_copy(&_call, call);

	_MANGLE_PATH(_call.oldpath, -1, old);
	_MANGLE_PATH(_call.newpath, -1, new);

	if (call->at && call->oldpath[0] != '/') {
		_call.oldpath = call->oldpath;
	}

	if (call->at && call->newpath[0] != '/') {
		_call.newpath = call->newpath;
	}

	return this->next->symlink(ctx, this->next->symlink_next, &_call);
}

static int rootlink_unlink(Context *ctx, const This *this,
						   const CallUnlink *call) {
	CallUnlink _call;
	callunlink_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->unlink(ctx, this->next->unlink_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->unlink(ctx, this->next->unlink_next, &_call);
}

static ssize_t rootlink_xattr(Context *ctx, const This *this,
							  const CallXattr *call) {
	CallXattr _call;
	callxattr_copy(&_call, call);

	if (call->type2 == XATTRTYPE_F) {
		return this->next->xattr(ctx, this->next->xattr_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->xattr(ctx, this->next->xattr_next, &_call);
}

static int rootlink_rename(Context *ctx, const This *this,
						   const CallRename *call) {
	CallRename _call;
	callrename_copy(&_call, call);

	_MANGLE_PATH(_call.oldpath, -1, old);
	_MANGLE_PATH(_call.newpath, -1, new);

	if (renametype_is_at(call->type) && call->oldpath[0] != '/') {
		_call.oldpath = call->oldpath;
	}

	if (renametype_is_at(call->type) && call->newpath[0] != '/') {
		_call.newpath = call->newpath;
	}

	return this->next->rename(ctx, this->next->rename_next, &_call);
}

static int rootlink_chdir(Context *ctx, const This *this,
						  const CallChdir *call) {
	CallChdir _call;
	callchdir_copy(&_call, call);

	if (call->f) {
		return this->next->chdir(ctx, this->next->chdir_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->chdir(ctx, this->next->chdir_next, &_call);
}

static int rootlink_chmod(Context *ctx, const This *this,
						  const CallChmod *call) {
	CallChmod _call;
	callchmod_copy(&_call, call);

	if ((chmodtype_is_at(call->type) && call->path[0] != '/') ||
			call->type == CHMODTYPE_F) {
		return this->next->chmod(ctx, this->next->chmod_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->chmod(ctx, this->next->chmod_next, &_call);
}

static int rootlink_truncate(Context *ctx, const This *this,
							 const CallTruncate *call) {
	CallTruncate _call;
	calltruncate_copy(&_call, call);

	if (call->f) {
		return this->next->truncate(ctx, this->next->truncate_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->truncate(ctx, this->next->truncate_next, &_call);
}

static int rootlink_mkdir(Context *ctx, const This *this,
						  const CallMkdir *call) {
	CallMkdir _call;
	callmkdir_copy(&_call, call);

	if (call->at && call->path[0] != '/') {
		return this->next->mkdir(ctx, this->next->mkdir_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->mkdir(ctx, this->next->mkdir_next, &_call);
}

const CallHandler *rootlink_init(const CallHandler *next) {
	static int initialized = 0;
	static This this;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this.next = next;
	this.this = *next;

	this.this.open = rootlink_open;
	this.this.open_next = &this;
	this.this.stat = rootlink_stat;
	this.this.stat_next = &this;
	this.this.readlink = rootlink_readlink;
	this.this.readlink_next = &this;
	this.this.access = rootlink_access;
	this.this.access_next = &this;
	this.this.exec = rootlink_exec;
	this.this.exec_next = &this;
	this.this.link = rootlink_link;
	this.this.link_next = &this;
	this.this.symlink = rootlink_symlink;
	this.this.symlink_next = &this;
	this.this.unlink = rootlink_unlink;
	this.this.unlink_next = &this;
	this.this.xattr = rootlink_xattr;
	this.this.xattr_next = &this;
	this.this.rename = rootlink_rename;
	this.this.rename_next = &this;
	this.this.chdir = rootlink_chdir;
	this.this.chdir_next = &this;
	this.this.chmod = rootlink_chmod;
	this.this.chmod_next = &this;
	this.this.truncate = rootlink_truncate;
	this.this.truncate_next = &this;
	this.this.mkdir = rootlink_mkdir;
	this.this.mkdir_next = &this;

	return &this.this;
}
