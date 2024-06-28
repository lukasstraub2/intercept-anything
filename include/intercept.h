#pragma once

#include "types.h"
#include "tls.h"

// I wanted 64k, but glibc vfork only allocates 32k stack
// TODO: Allocate on heap
#define SCRATCH_SIZE (12*1024)
_Static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

typedef struct Context Context;
struct Context {
	char scratch[SCRATCH_SIZE];
	Tls *tls;
};

typedef struct RetInt RetInt;
struct RetInt {
	int ret;
	int _errno;
};

typedef struct CallOpen CallOpen;
struct CallOpen {
	int at;
	int dirfd;
	const char *path;
	int flags;
	mode_t mode;
	RetInt *ret;
};

__attribute__((unused))
static void callopen_copy(CallOpen *dst, const CallOpen *call) {
	dst->at = call->at;

	if (call->at) {
		dst->dirfd = call->dirfd;
	}

	dst->path = call->path;
	dst->flags = call->flags;
	dst->mode = call->mode;
	dst->ret = call->ret;
}

typedef enum StatType StatType;
enum StatType {
	STATTYPE_PLAIN = 0,
	STATTYPE_F,
	STATTYPE_L,
	STATTYPE_AT,
	STATTYPE_X
};
__attribute__((unused))
static int stattype_is_at(StatType type) {
	return type >= STATTYPE_AT;
}

typedef struct CallStat CallStat;
struct CallStat {
	StatType type;
	int dirfd;
	const char *path;
	int flags;
	unsigned int mask;
	void *statbuf;
	RetInt *ret;
};

__attribute__((unused))
static void callstat_copy(CallStat *dst, const CallStat *call) {
	dst->type = call->type;

	if (stattype_is_at(call->type)) {
		dst->dirfd = call->dirfd;
		dst->flags = call->flags;
	}

	if (call->type == STATTYPE_F) {
		dst->dirfd = call->dirfd;
	} else {
		dst->path = call->path;
	}

	if (call->type == STATTYPE_X) {
		dst->mask = call->mask;
	}

	dst->statbuf = call->statbuf;
	dst->ret = call->ret;
}

typedef struct RetSSize RetSSize;
struct RetSSize {
	ssize_t ret;
	int _errno;
};

typedef struct CallReadlink CallReadlink;
struct CallReadlink {
	int at;
	int dirfd;
	const char *path;
	char *buf;
	size_t bufsiz;
	RetSSize *ret;
};

__attribute__((unused))
static void callreadlink_copy(CallReadlink *dst, const CallReadlink *call) {
	dst->at = call->at;

	if (call->at) {
		dst->dirfd = call->dirfd;
	}

	dst->path = call->path;
	dst->buf = call->buf;
	dst->bufsiz = call->bufsiz;
	dst->ret = call->ret;
}

typedef struct CallAccess CallAccess;
struct CallAccess {
	int at;
	int dirfd;
	const char *path;
	int mode;
	RetInt *ret;
};

__attribute__((unused))
static void callaccess_copy(CallAccess *dst, const CallAccess *call) {
	dst->at = call->at;

	if (call->at) {
		dst->dirfd = call->dirfd;
	}

	dst->path = call->path;
	dst->mode = call->mode;
	dst->ret = call->ret;
}

typedef struct CallExec CallExec;
struct CallExec {
	int at;
	int final;
	int dirfd;
	const char *path;
	char *const *argv;
	char *const *envp;
	int flags;
	RetInt *ret;
};

__attribute__((unused))
static void callexec_copy(CallExec *dst, const CallExec *call) {
	dst->at = call->at;
	dst->final = call->final;

	if (call->at) {
		dst->dirfd = call->dirfd;
		dst->flags = call->flags;
	}

	dst->path = call->path;
	dst->argv = call->argv;
	dst->envp = call->envp;
	dst->ret = call->ret;
}

typedef struct CallLink CallLink;
struct CallLink {
	int at;
	int olddirfd;
	const char *oldpath;
	int newdirfd;
	const char *newpath;
	int flags;
	RetInt *ret;
};

typedef struct CallUnlink CallUnlink;
struct CallUnlink {
	int at;
	int dirfd;
	const char *path;
	int flags;
	RetInt *ret;
};

typedef enum XattrType XattrType;
enum XattrType {
	XATTRTYPE_SET,
	XATTRTYPE_GET,
	XATTRTYPE_LIST,
	XATTRTYPE_REMOVE
};

typedef enum XattrType2 XattrType2;
enum XattrType2 {
	XATTRTYPE_PLAIN,
	XATTRTYPE_L,
	XATTRTYPE_F
};

typedef struct CallXattr CallXattr;
struct CallXattr {
	XattrType type;
	XattrType2 type2;
	union {
		int fd;
		const char *path;
	};
	union {
		char *list;
		struct {
			const char *name;
			void *value;
		};
	};
	size_t size;
	int flags;
	RetSSize *ret;
};

__attribute__((unused))
static void callxattr_copy(CallXattr *dst, const CallXattr *call) {
	dst->type = call->type;
	dst->type2 = call->type2;

	if (call->type2 == XATTRTYPE_F) {
		dst->fd = call->fd;
	} else {
		dst->path = call->path;
	}

	switch (call->type) {
		case XATTRTYPE_SET:
			dst->flags = call->flags;
		/*fallthrough*/
		case XATTRTYPE_GET:
			dst->name = call->name;
			dst->value = call->value;
			dst->size = call->size;
		break;

		case XATTRTYPE_LIST:
			dst->list = call->list;
			dst->size = call->size;
		break;

		case XATTRTYPE_REMOVE:
			dst->name = call->name;
		break;
	}

	dst->ret = call->ret;
}

typedef enum RenameType RenameType;
enum RenameType {
	RENAMETYPE_PLAIN,
	RENAMETYPE_AT,
	RENAMETYPE_AT2
};
__attribute__((unused))
static int renametype_is_at(RenameType type) {
	return type >= RENAMETYPE_AT;
}

typedef struct CallRename CallRename;
struct CallRename {
	RenameType type;
	int olddirfd;
	const char *oldpath;
	int newdirfd;
	const char *newpath;
	unsigned int flags;
	RetInt *ret;
};

__attribute__((unused))
static void callrename_copy(CallRename *dst, const CallRename *call) {
	dst->type = call->type;

	if (renametype_is_at(call->type)) {
		dst->olddirfd = call->olddirfd;
		dst->newdirfd = call->newdirfd;
	}

	dst->oldpath = call->oldpath;
	dst->newpath = call->newpath;

	if (call->type == RENAMETYPE_AT2) {
		dst->flags = call->flags;
	}

	dst->ret = call->ret;
}

typedef struct This This;
typedef struct CallHandler CallHandler;
struct CallHandler {
	int (*open)(Context *ctx, const This *this, const CallOpen *call);
	const This *open_next;
	int (*stat)(Context *ctx, const This *this, const CallStat *call);
	const This *stat_next;
	ssize_t (*readlink)(Context *ctx, const This *this, const CallReadlink *call);
	const This *readlink_next;
	int (*access)(Context *ctx, const This *this, const CallAccess *call);
	const This *access_next;
	int (*exec)(Context *ctx, const This *this, const CallExec *call);
	const This *exec_next;
	int (*link)(Context *ctx, const This *this, const CallLink *call);
	const This *link_next;
	int (*symlink)(Context *ctx, const This *this, const CallLink *call);
	const This *symlink_next;
	int (*unlink)(Context *ctx, const This *this, const CallUnlink *call);
	const This *unlink_next;
	ssize_t (*xattr)(Context *ctx, const This *this, const CallXattr *call);
	const This *xattr_next;
	int (*rename)(Context *ctx, const This *this, const CallRename *call);
	const This *rename_next;
};

void intercept_init(int recursing);
const CallHandler *main_init(const CallHandler *bottom);
