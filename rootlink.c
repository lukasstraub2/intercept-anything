
#include "common.h"

#include "rootlink.h"
#include "config.h"
#include "intercept.h"
#include "util.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

struct This {
	CallHandler this;
	const CallHandler *next;
};

static int handle_path(const char *path) {
	return !strcmp_prefix(path, "/usr") ||
			!strcmp_prefix(path, "/bin");
}

static size_t mangle_path(char *out, size_t out_len, const char *path) {
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

#define MANGLE_PATH(__path, errret) \
	size_t len = mangle_path(NULL, 0, (__path)); \
	if (len > (64 * 1024)) { \
		call->ret->_errno = ENAMETOOLONG; \
		call->ret->ret = (errret); \
		return (errret); \
	} \
	\
	char buf[len]; \
	len = mangle_path(buf, len, (__path)); \
	assert(len >= 0); \
	(__path) = buf

static int rootlink_open(Context *ctx, const This *this,
						 const CallOpen *call) {
	CallOpen _call;
	callopen_copy(&_call, call);

	if (opentype_is_at(call->type) && call->path[0] != '/') {
		return this->next->open(ctx, this->next->open_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->open(ctx, this->next->open_next, &_call);
}

static FILE *rootlink_fopen(Context *ctx, const This *this,
							const CallFOpen *call) {
	CallFOpen _call;
	callfopen_copy(&_call, call);

	MANGLE_PATH(_call.path, NULL);
	return this->next->fopen(ctx, this->next->fopen_next, &_call);
}

static DIR *rootlink_opendir(Context *ctx, const This *this,
							 const CallOpendir *call) {
	CallOpendir _call;
	callopendir_copy(&_call, call);

	MANGLE_PATH(_call.path, NULL);
	return this->next->opendir(ctx, this->next->opendir_next, &_call);
}

static int rootlink_stat(Context *ctx, const This *this,
						 const CallStat *call) {
	CallStat _call;
	callstat_copy(&_call, call);

	if (stattype_is_at(call->type) && call->path[0] != '/') {
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

	if (accesstype_is_at(call->type) && call->path[0] != '/') {
		return this->next->access(ctx, this->next->access_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->access(ctx, this->next->access_next, &_call);
}

static int rootlink_exec(Context *ctx, const This *this,
						 const CallExec *call) {
	CallExec _call;
	callexec_copy(&_call, call);

	if (exectype_is_at(call->type) && call->path[0] != '/') {
		return this->next->exec(ctx, this->next->exec_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->exec(ctx, this->next->exec_next, &_call);
}

static char *rootlink_realpath(Context *ctx, const This *this,
							   const CallRealpath *call) {
	CallRealpath _call;
	callrealpath_copy(&_call, call);

	MANGLE_PATH(_call.path, NULL);
	return this->next->realpath(ctx, this->next->realpath_next, &_call);
}

static ssize_t rootlink_listxattr(Context *ctx, const This *this,
								  const CallListXattr *call) {
	CallListXattr _call;
	calllistxattr_copy(&_call, call);

	if (call->type == XATTRTYPE_F) {
		return this->next->listxattr(ctx, this->next->listxattr_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->listxattr(ctx, this->next->listxattr_next, &_call);
}

static ssize_t rootlink_getxattr(Context *ctx, const This *this,
								 const CallGetXattr *call) {
	CallGetXattr _call;
	callgetxattr_copy(&_call, call);

	if (call->type == XATTRTYPE_F) {
		return this->next->getxattr(ctx, this->next->getxattr_next, call);
	}

	MANGLE_PATH(_call.path, -1);
	return this->next->getxattr(ctx, this->next->getxattr_next, &_call);
}

// Provide only readonly functions for now
// int rootlink_link(Context *ctx, const This *this, CallLink *call);
// int rootlink_symlink(Context *ctx, const This *this, CallLink *call);
// int rootlink_unlink(Context *ctx, const This *this, CallUnlink *call);
// int rootlink_setxattr(Context *ctx, const This *this, CallSetXattr *call);
// int rootlink_rename(Context *ctx, const This *this, CallRename *call);

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
	this.this.fopen = rootlink_fopen;
	this.this.fopen_next = &this;
	this.this.opendir = rootlink_opendir;
	this.this.opendir_next = &this;
	this.this.stat = rootlink_stat;
	this.this.stat_next = &this;
	this.this.readlink = rootlink_readlink;
	this.this.readlink_next = &this;
	this.this.access = rootlink_access;
	this.this.access_next = &this;
	this.this.exec = rootlink_exec;
	this.this.exec_next = &this;
	this.this.realpath = rootlink_realpath;
	this.this.realpath_next = &this;
	this.this.listxattr = rootlink_listxattr;
	this.this.listxattr_next = &this;
	this.this.getxattr = rootlink_getxattr;
	this.this.getxattr_next = &this;

	return &this.this;
}
