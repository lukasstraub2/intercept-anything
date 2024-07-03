#pragma once

#include "types.h"
#include "tls.h"
#include "config.h"

typedef struct Context Context;
struct Context {
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

__attribute__((unused))
static void calllink_copy(CallLink *dst, const CallLink *call) {
	dst->at = call->at;

	if (dst->at) {
		dst->olddirfd = call->olddirfd;
		dst->newdirfd = call->newdirfd;
		dst->flags = call->flags;
	}

	dst->oldpath = call->oldpath;
	dst->newpath = call->newpath;
	dst->ret = call->ret;
}

typedef struct CallUnlink CallUnlink;
struct CallUnlink {
	int at;
	int dirfd;
	const char *path;
	int flags;
	RetInt *ret;
};

__attribute__((unused))
static void callunlink_copy(CallUnlink *dst, const CallUnlink *call) {
	dst->at = call->at;

	if (dst->at) {
		dst->dirfd = call->dirfd;
		dst->flags = call->flags;
	}

	dst->path = call->path;
	dst->ret = call->ret;
}

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

typedef struct CallChdir CallChdir;
struct CallChdir {
	int f;
	int fd;
	const char *path;
	RetInt *ret;
};

__attribute__((unused))
static void callchdir_copy(CallChdir *dst, const CallChdir *call) {
	dst->f = call->f;
	if (call->f) {
		dst->fd = call->fd;
	} else {
		dst->path = call->path;
	}
	dst->ret = call->ret;
}

typedef enum ChmodType ChmodType;
enum ChmodType {
	CHMODTYPE_PLAIN,
	CHMODTYPE_F,
	CHMODTYPE_AT,
};
__attribute__((unused))
static int chmodtype_is_at(ChmodType type) {
	return type == CHMODTYPE_AT;
}

// New structure for chmod calls
typedef struct CallChmod CallChmod;
struct CallChmod {
	ChmodType type;
	int fd;
	int dirfd;
	const char *path;
	mode_t mode;
	RetInt *ret;
};

__attribute__((unused))
static void callchmod_copy(CallChmod *dst, const CallChmod *call) {
	dst->type = call->type;
	if (chmodtype_is_at(call->type)) {
		dst->dirfd = call->dirfd;
	} else if (call->type == CHMODTYPE_F) {
		dst->fd = call->fd;
	}
	dst->path = call->path;
	dst->mode = call->mode;
	dst->ret = call->ret;
}

typedef struct CallTruncate CallTruncate;
struct CallTruncate {
	int f;
	int fd;
	const char *path;
	off_t length;
	RetInt *ret;
};

__attribute__((unused))
static void calltruncate_copy(CallTruncate *dst, const CallTruncate *call) {
	dst->f = call->f;
	if (call->f) {
		dst->fd = call->fd;
	} else {
		dst->path = call->path;
	}
	dst->length = call->length;
	dst->ret = call->ret;
}

typedef struct CallMkdir CallMkdir;
struct CallMkdir {
	int at;
	int dirfd;
	const char *path;
	mode_t mode;
	RetInt *ret;
};

__attribute__((unused))
static void callmkdir_copy(CallMkdir *dst, const CallMkdir *call) {
	dst->at = call->at;
	if (call->at) {
		dst->dirfd = call->dirfd;
	}
	dst->path = call->path;
	dst->mode = call->mode;
	dst->ret = call->ret;
}

typedef struct CallGetdents CallGetdents;
struct CallGetdents {
	int is64;
	int fd;
	void *dirp;
	size_t count;
	RetSSize *ret;
};

__attribute__((unused))
static void callgetdents_copy(CallGetdents *dst, const CallGetdents *call) {
	dst->is64 = call->is64;
	dst->fd = call->fd;
	dst->dirp = call->dirp;
	dst->count = call->count;
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
	int (*chdir)(Context *ctx, const This *this, const CallChdir *call);
	const This *chdir_next;
	int (*chmod)(Context *ctx, const This *this, const CallChmod *call);
	const This *chmod_next;
	int (*truncate)(Context *ctx, const This *this, const CallTruncate *call);
	const This *truncate_next;
	int (*mkdir)(Context *ctx, const This *this, const CallMkdir *call);
	const This *mkdir_next;
	ssize_t (*getdents)(Context *ctx, const This *this, const CallGetdents *call);
	const This *getdents_next;
};

extern const char *self_exe;

void intercept_init(int recursing, const char *exe);
const CallHandler *main_init(const CallHandler *bottom);

int handle_openat(int dirfd, const char *path, int flags, mode_t mode);
