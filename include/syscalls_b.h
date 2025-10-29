#pragma once

#include "base_types.h"
#include "myseccomp.h"

#include <sys/types.h>

struct CallLink {
    int at;
    int olddirfd;
    const char* oldpath;
    int newdirfd;
    const char* newpath;
    int flags;
    int* ret;
};
typedef struct CallLink CallLink;

__attribute__((unused)) static void calllink_copy(CallLink* dst,
                                                  const CallLink* call) {
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

struct CallUnlink {
    int at;
    int dirfd;
    const char* path;
    int flags;
    int* ret;
};
typedef struct CallUnlink CallUnlink;

__attribute__((unused)) static void callunlink_copy(CallUnlink* dst,
                                                    const CallUnlink* call) {
    dst->at = call->at;

    if (dst->at) {
        dst->dirfd = call->dirfd;
        dst->flags = call->flags;
    }

    dst->path = call->path;
    dst->ret = call->ret;
}

enum RenameType { RENAMETYPE_PLAIN, RENAMETYPE_AT, RENAMETYPE_AT2 };
typedef enum RenameType RenameType;

__attribute__((unused)) static int renametype_is_at(RenameType type) {
    return type >= RENAMETYPE_AT;
}

struct CallRename {
    RenameType type;
    int olddirfd;
    const char* oldpath;
    int newdirfd;
    const char* newpath;
    unsigned int flags;
    int* ret;
};
typedef struct CallRename CallRename;

__attribute__((unused)) static void callrename_copy(CallRename* dst,
                                                    const CallRename* call) {
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

enum ChmodType {
    CHMODTYPE_PLAIN,
    CHMODTYPE_F,
    CHMODTYPE_AT,
};
typedef enum ChmodType ChmodType;

__attribute__((unused)) static int chmodtype_is_at(ChmodType type) {
    return type == CHMODTYPE_AT;
}

// New structure for chmod calls
struct CallChmod {
    ChmodType type;
    int fd;
    int dirfd;
    const char* path;
    mode_t mode;
    int* ret;
};
typedef struct CallChmod CallChmod;

__attribute__((unused)) static void callchmod_copy(CallChmod* dst,
                                                   const CallChmod* call) {
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

struct CallTruncate {
    int f;
    int fd;
    const char* path;
    off_t length;
    int* ret;
};
typedef struct CallTruncate CallTruncate;

__attribute__((unused)) static void calltruncate_copy(
    CallTruncate* dst,
    const CallTruncate* call) {
    dst->f = call->f;
    if (call->f) {
        dst->fd = call->fd;
    } else {
        dst->path = call->path;
    }
    dst->length = call->length;
    dst->ret = call->ret;
}

struct CallMkdir {
    int at;
    int dirfd;
    const char* path;
    mode_t mode;
    int* ret;
};
typedef struct CallMkdir CallMkdir;

__attribute__((unused)) static void callmkdir_copy(CallMkdir* dst,
                                                   const CallMkdir* call) {
    dst->at = call->at;
    if (call->at) {
        dst->dirfd = call->dirfd;
    }
    dst->path = call->path;
    dst->mode = call->mode;
    dst->ret = call->ret;
}

struct CallMknod {
    int at;     // Indicates if dirfd is used (1) or not (0)
    int dirfd;  // File descriptor of the directory (if at == 1)
    const char* path;
    mode_t mode;
    unsigned int dev;  // Device number
    int* ret;
};
typedef struct CallMknod CallMknod;

__attribute__((unused)) static void callmknod_copy(CallMknod* dst,
                                                   const CallMknod* call) {
    dst->at = call->at;
    if (call->at) {
        dst->dirfd = call->dirfd;
    }
    dst->path = call->path;
    dst->mode = call->mode;
    dst->dev = call->dev;
    dst->ret = call->ret;
}

unsigned long handle_link(Context* ctx, SysArgs* args);
unsigned long handle_linkat(Context* ctx, SysArgs* args);
unsigned long handle_symlink(Context* ctx, SysArgs* args);
unsigned long handle_symlinkat(Context* ctx, SysArgs* args);
unsigned long handle_unlink(Context* ctx, SysArgs* args);
unsigned long handle_unlinkat(Context* ctx, SysArgs* args);
unsigned long handle_rename(Context* ctx, SysArgs* args);
unsigned long handle_renameat(Context* ctx, SysArgs* args);
unsigned long handle_renameat2(Context* ctx, SysArgs* args);
unsigned long handle_chmod(Context* ctx, SysArgs* args);
unsigned long handle_fchmod(Context* ctx, SysArgs* args);
unsigned long handle_fchmodat(Context* ctx, SysArgs* args);
unsigned long handle_truncate(Context* ctx, SysArgs* args);
unsigned long handle_ftruncate(Context* ctx, SysArgs* args);
unsigned long handle_mkdir(Context* ctx, SysArgs* args);
unsigned long handle_mkdirat(Context* ctx, SysArgs* args);
unsigned long handle_mknod(Context* ctx, SysArgs* args);
unsigned long handle_mknodat(Context* ctx, SysArgs* args);

void syscalls_b_fill_bottom(CallHandler* bottom);