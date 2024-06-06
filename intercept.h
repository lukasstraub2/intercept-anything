#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <spawn.h>

#define SCRATCH_SIZE (64*1024)
_Static_assert(SCRATCH_SIZE >= PATH_MAX, "SCRATCH_SIZE");

typedef struct Context Context;
struct Context {
	char scratch[SCRATCH_SIZE];
};

typedef struct RetInt RetInt;
struct RetInt {
	int ret;
	int _errno;
};

typedef enum OpenType OpenType;
enum OpenType {
	OPENTYPE_PLAIN = 0,
	OPENTYPE_64,
	OPENTYPE_2,
	OPENTYPE_64_2,
	OPENTYPE_AT,
	OPENTYPE_AT_64,
	OPENTYPE_AT_2,
	OPENTYPE_AT_64_2
};

enum OpenTypeBit {
	OPENTYPE_BIT_64 = (1 << 0),
	OPENTYPE_BIT_2 = (1 << 1),
	OPENTYPE_BIT_AT = (1 << 2)
};

static int opentype_is_at(OpenType type) {
	return type & OPENTYPE_BIT_AT;
}

static int opentype_is_2(OpenType type) {
	return type & OPENTYPE_BIT_2;
}

typedef struct CallOpen CallOpen;
struct CallOpen {
	OpenType type;
	int dirfd;
	const char *path;
	int flags;
	mode_t mode;
	RetInt *ret;
};

static void callopen_copy(CallOpen *dst, const CallOpen *call) {
	dst->type = call->type;

	if (opentype_is_at(call->type)) {
		dst->dirfd = call->dirfd;
	}

	dst->path = call->path;
	dst->flags = call->flags;

	if (!opentype_is_2(call->type)) {
		dst->mode = call->mode;
	}

	dst->ret = call->ret;
}

typedef struct RetPtr RetPtr;
struct RetPtr {
	void *ret;
	int _errno;
};

typedef struct CallFOpen CallFOpen;
struct CallFOpen {
	int fopen64;
	const char *path;
	const char *mode;
	RetPtr *ret;
};

static void callfopen_copy(CallFOpen *dst, const CallFOpen *call) {
	*dst = *call;
}

typedef struct CallOpendir CallOpendir;
struct CallOpendir {
	const char *path;
	RetPtr *ret;
};

static void callopendir_copy(CallOpendir *dst, const CallOpendir *call) {
	*dst = *call;
}

typedef enum StatType StatType;
enum StatType {
	STATTYPE_PLAIN = 0,
	STATTYPE_64,
	STATTYPE___X,
	STATTYPE___X_64,
	STATTYPE_L,
	STATTYPE_L_64,
	STATTYPE_AT,
	STATTYPE_AT_64,

	STATTYPE_X = 9
};
static int stattype_is_at(StatType type) {
	return type >= STATTYPE_AT;
}

typedef struct CallStat CallStat;
struct CallStat {
	StatType type;
	int ver;
	int dirfd;
	const char *path;
	int flags;
	unsigned int mask;
	void *statbuf;
	RetInt *ret;
};

static void callstat_copy(CallStat *dst, const CallStat *call) {
	dst->type = call->type;

	if (call->type == STATTYPE___X || call->type == STATTYPE___X_64) {
		dst->ver = call->ver;
	}

	if (stattype_is_at(call->type)) {
		dst->dirfd = call->dirfd;
		dst->flags = call->flags;
	}

	dst->path = call->path;

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
_Static_assert(sizeof(ssize_t) == sizeof(signed long), "sizeof(ssize_t)");
_Static_assert(sizeof(size_t) == sizeof(long), "sizeof(size_t)");

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

typedef enum AccessType AccessType;
enum AccessType {
	ACCESSTYPE_PLAIN,
	ACCESSTYPE_AT,
	ACCESSTYPE_EUID,
	ACCESSTYPE_E
};
static int accesstype_is_at(AccessType type) {
	return type == ACCESSTYPE_AT;
}

typedef struct CallAccess CallAccess;
struct CallAccess {
	AccessType type;
	int dirfd;
	const char *path;
	int mode;
	int flags;
	RetInt *ret;
};

static void callaccess_copy(CallAccess *dst, const CallAccess *call) {
	dst->type = call->type;

	if (accesstype_is_at(call->type)) {
		dst->dirfd = call->dirfd;
		dst->flags = call->flags;
	}

	dst->path = call->path;
	dst->mode = call->mode;
	dst->ret = call->ret;
}

typedef enum ExecType ExecType;
enum ExecType {
	EXECTYPE_EXECVE,
	EXECTYPE_EXECVE_AT,
	EXECTYPE_POSIX_SPAWN,
	EXECTYPE_POSIX_SPAWNP
};
static int exectype_is_at(ExecType type) {
	return type == EXECTYPE_EXECVE_AT;
}

typedef struct CallExec CallExec;
struct CallExec {
	ExecType type;
	int final;
	union {
		struct {
			int dirfd;
			int flags;
		};
		struct {
			pid_t *pid;
			const posix_spawn_file_actions_t *file_actions;
			const posix_spawnattr_t *attrp;
		};
	};
	const char *path;
	char *const *argv;
	char *const *envp;
	RetInt *ret;
};

static void callexec_copy(CallExec *dst, const CallExec *call) {
	dst->type = call->type;
	dst->final = call->final;

	switch (call->type) {
		case EXECTYPE_EXECVE:
		break;

		case EXECTYPE_EXECVE_AT:
			dst->dirfd = call->dirfd;
			dst->flags = call->flags;
		break;

		case EXECTYPE_POSIX_SPAWN:
		case EXECTYPE_POSIX_SPAWNP:
			dst->pid = call->pid;
			dst->file_actions = call->file_actions;
			dst->attrp = call->attrp;
		break;
	}

	dst->path = call->path;
	dst->argv = call->argv;
	dst->envp = call->envp;
	dst->ret = call->ret;
}

typedef struct CallRealpath CallRealpath;
struct CallRealpath {
	const char *path;
	char *out;
	RetPtr *ret;
};

static void callrealpath_copy(CallRealpath *dst, const CallRealpath *call) {
	*dst = *call;
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
	XATTRTYPE_PLAIN,
	XATTRTYPE_L,
	XATTRTYPE_F
};

typedef struct CallListXattr CallListXattr;
struct CallListXattr {
	XattrType type;
	int fd;
	const char *path;
	char *list;
	size_t size;
	RetSSize *ret;
};

static void calllistxattr_copy(CallListXattr *dst, const CallListXattr *call) {
	dst->type = call->type;

	if (call->type == XATTRTYPE_F) {
		dst->fd = call->fd;
	} else {
		dst->path = call->path;
	}

	dst->list = call->list;
	dst->size = call->size;
	dst->ret = call->ret;
}

typedef struct CallSetXattr CallSetXattr;
struct CallSetXattr {
	XattrType type;
	int fd;
	const char *path;
	const char *name;
	const void *value;
	size_t size;
	int flags;
	RetInt *ret;
};

static void callsetxattr_copy(CallSetXattr *dst, const CallSetXattr *call) {
	dst->type = call->type;

	if (call->type == XATTRTYPE_F) {
		dst->fd = call->fd;
	} else {
		dst->path = call->path;
	}

	dst->name = call->name;
	dst->value = call->value;
	dst->size = call->size;
	dst->flags = call->flags;
	dst->ret = call->ret;
}

typedef struct CallGetXattr CallGetXattr;
struct CallGetXattr {
	XattrType type;
	int fd;
	const char *path;
	const char *name;
	void *value;
	size_t size;
	RetSSize *ret;
};

static void callgetxattr_copy(CallGetXattr *dst, const CallGetXattr *call) {
	dst->type = call->type;

	if (call->type == XATTRTYPE_F) {
		dst->fd = call->fd;
	} else {
		dst->path = call->path;
	}

	dst->name = call->name;
	dst->value = call->value;
	dst->size = call->size;
	dst->ret = call->ret;
}

typedef enum RenameType RenameType;
enum RenameType {
	RENAMETYPE_PLAIN,
	RENAMETYPE_AT,
	RENAMETYPE_AT2
};
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

typedef struct CallScandir CallScandir;
struct CallScandir {
	int at;
	int dirfd;
	const char *restrict dirp;
	struct dirent ***restrict namelist;
	int (*filter)(const struct dirent *);
	int (*compar)(const struct dirent **, const struct dirent **);
	RetInt *ret;
};

typedef struct CallChdir CallChdir;
struct CallChdir {
	int fd;
	const char *path;
	RetInt *ret;
};

typedef enum MktempType MktempType;
enum MktempType {
	MKTEMPTYPE_PLAIN,
	MKTEMPTYPE_MKS,
	MKTEMPTYPE_MKOS,
	MKTEMPTYPE_MKS_S,
	MKTEMPTYPE_MKOS_S
};

typedef struct CallMktemp CallMktemp;
struct CallMktemp {
	MktempType type;
	char *template;
	int flags;
	int suffixlen;
	RetPtr *ret;
};

typedef struct This This;
typedef struct CallHandler CallHandler;
struct CallHandler {
	int (*open)(Context *ctx, const This *this, const CallOpen *call);
	const This *open_next;
	FILE *(*fopen)(Context *ctx, const This *this, const CallFOpen *call);
	const This *fopen_next;
	DIR *(*opendir)(Context *ctx, const This *this, const CallOpendir *call);
	const This *opendir_next;
	int (*stat)(Context *ctx, const This *this, const CallStat *call);
	const This *stat_next;
	ssize_t (*readlink)(Context *ctx, const This *this, const CallReadlink *call);
	const This *readlink_next;
	int (*access)(Context *ctx, const This *this, const CallAccess *call);
	const This *access_next;
	int (*exec)(Context *ctx, const This *this, const CallExec *call);
	const This *exec_next;
	char *(*realpath)(Context *ctx, const This *this, const CallRealpath *call);
	const This *realpath_next;
	int (*link)(Context *ctx, const This *this, const CallLink *call);
	const This *link_next;
	int (*symlink)(Context *ctx, const This *this, const CallLink *call);
	const This *symlink_next;
	int (*unlink)(Context *ctx, const This *this, const CallUnlink *call);
	const This *unlink_next;
	ssize_t (*listxattr)(Context *ctx, const This *this, const CallListXattr *call);
	const This *listxattr_next;
	int (*setxattr)(Context *ctx, const This *this, const CallSetXattr *call);
	const This *setxattr_next;
	ssize_t (*getxattr)(Context *ctx, const This *this, const CallGetXattr *call);
	const This *getxattr_next;
	int (*rename)(Context *ctx, const This *this, const CallRename *call);
	const This *rename_next;
	int (*scandir)(Context *ctx, const This *this, const CallScandir *call);
	const This *scandir_next;
	int (*chdir)(Context *ctx, const This *this, const CallChdir *call);
	const This *chdir_next;
	void *(*mktemp)(Context *ctx, const This *this, const CallMktemp *call);
	const This *mktemp_next;
};

const CallHandler *main_init(const CallHandler *bottom);
