#pragma once

#include "base_types.h"
#include "myseccomp.h"

#include <sys/types.h>

struct CallOpen {
    int at;
    int dirfd;
    const char* path;
    int flags;
    mode_t mode;
    int* ret;
};
typedef struct CallOpen CallOpen;

__attribute__((unused)) static void callopen_copy(CallOpen* dst,
                                                  const CallOpen* call) {
    dst->at = call->at;

    if (call->at) {
        dst->dirfd = call->dirfd;
    }

    dst->path = call->path;
    dst->flags = call->flags;
    dst->mode = call->mode;
    dst->ret = call->ret;
}

enum StatType {
    STATTYPE_PLAIN = 0,
    STATTYPE_F,
    STATTYPE_L,
    STATTYPE_AT,
    STATTYPE_X
};
typedef enum StatType StatType;
__attribute__((unused)) static int stattype_is_at(StatType type) {
    return type >= STATTYPE_AT;
}

struct CallStat {
    StatType type;
    int dirfd;
    const char* path;
    int flags;
    unsigned int mask;
    void* statbuf;
    int* ret;
};
typedef struct CallStat CallStat;

__attribute__((unused)) static void callstat_copy(CallStat* dst,
                                                  const CallStat* call) {
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

struct CallReadlink {
    int at;
    int dirfd;
    const char* path;
    char* buf;
    size_t bufsiz;
    ssize_t* ret;
};
typedef struct CallReadlink CallReadlink;

__attribute__((unused)) static void callreadlink_copy(
    CallReadlink* dst,
    const CallReadlink* call) {
    dst->at = call->at;

    if (call->at) {
        dst->dirfd = call->dirfd;
    }

    dst->path = call->path;
    dst->buf = call->buf;
    dst->bufsiz = call->bufsiz;
    dst->ret = call->ret;
}

struct CallAccess {
    int at;
    int dirfd;
    const char* path;
    int mode;
    int* ret;
};
typedef struct CallAccess CallAccess;

__attribute__((unused)) static void callaccess_copy(CallAccess* dst,
                                                    const CallAccess* call) {
    dst->at = call->at;

    if (call->at) {
        dst->dirfd = call->dirfd;
    }

    dst->path = call->path;
    dst->mode = call->mode;
    dst->ret = call->ret;
}

enum XattrType {
    XATTRTYPE_SET,
    XATTRTYPE_GET,
    XATTRTYPE_LIST,
    XATTRTYPE_REMOVE
};
typedef enum XattrType XattrType;

enum XattrType2 { XATTRTYPE_PLAIN, XATTRTYPE_L, XATTRTYPE_F };
typedef enum XattrType2 XattrType2;

struct CallXattr {
    XattrType type;
    XattrType2 type2;
    union {
        int fd;
        const char* path;
    };
    union {
        char* list;
        struct {
            const char* name;
            void* value;
        };
    };
    size_t size;
    int flags;
    ssize_t* ret;
};
typedef struct CallXattr CallXattr;

__attribute__((unused)) static void callxattr_copy(CallXattr* dst,
                                                   const CallXattr* call) {
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

struct CallChdir {
    int f;
    int fd;
    const char* path;
    int* ret;
};
typedef struct CallChdir CallChdir;

__attribute__((unused)) static void callchdir_copy(CallChdir* dst,
                                                   const CallChdir* call) {
    dst->f = call->f;
    if (call->f) {
        dst->fd = call->fd;
    } else {
        dst->path = call->path;
    }
    dst->ret = call->ret;
}

struct CallGetdents {
    int is64;
    int fd;
    void* dirp;
    size_t count;
    ssize_t* ret;
};
typedef struct CallGetdents CallGetdents;

__attribute__((unused)) static void callgetdents_copy(
    CallGetdents* dst,
    const CallGetdents* call) {
    dst->is64 = call->is64;
    dst->fd = call->fd;
    dst->dirp = call->dirp;
    dst->count = call->count;
    dst->ret = call->ret;
}

struct CallClose {
    int is_range;
    unsigned int fd;
    unsigned int max_fd;  // Only used for close_range
    unsigned int flags;   // Only used for close_range
    int* ret;
};
typedef struct CallClose CallClose;

__attribute__((unused)) static void callclose_copy(CallClose* dst,
                                                   const CallClose* call) {
    dst->is_range = call->is_range;
    dst->fd = call->fd;
    if (call->is_range) {
        dst->max_fd = call->max_fd;
        dst->flags = call->flags;
    }
    dst->ret = call->ret;
}

unsigned long handle_open(Context* ctx, SysArgs* args);
unsigned long handle_openat(Context* ctx, SysArgs* args);
unsigned long handle_stat(Context* ctx, SysArgs* args);
unsigned long handle_fstat(Context* ctx, SysArgs* args);
unsigned long handle_lstat(Context* ctx, SysArgs* args);
unsigned long handle_newfstatat(Context* ctx, SysArgs* args);
unsigned long handle_statx(Context* ctx, SysArgs* args);
unsigned long handle_readlink(Context* ctx, SysArgs* args);
unsigned long handle_readlinkat(Context* ctx, SysArgs* args);
unsigned long handle_access(Context* ctx, SysArgs* args);
unsigned long handle_faccessat(Context* ctx, SysArgs* args);
unsigned long handle_setxattr(Context* ctx, SysArgs* args);
unsigned long handle_lsetxattr(Context* ctx, SysArgs* args);
unsigned long handle_fsetxattr(Context* ctx, SysArgs* args);
unsigned long handle_getxattr(Context* ctx, SysArgs* args);
unsigned long handle_lgetxattr(Context* ctx, SysArgs* args);
unsigned long handle_fgetxattr(Context* ctx, SysArgs* args);
unsigned long handle_listxattr(Context* ctx, SysArgs* args);
unsigned long handle_llistxattr(Context* ctx, SysArgs* args);
unsigned long handle_flistxattr(Context* ctx, SysArgs* args);
unsigned long handle_removexattr(Context* ctx, SysArgs* args);
unsigned long handle_lremovexattr(Context* ctx, SysArgs* args);
unsigned long handle_fremovexattr(Context* ctx, SysArgs* args);
unsigned long handle_chdir(Context* ctx, SysArgs* args);
unsigned long handle_fchdir(Context* ctx, SysArgs* args);
unsigned long handle_getdents(Context* ctx, SysArgs* args);
unsigned long handle_getdents64(Context* ctx, SysArgs* args);
unsigned long handle_close(Context* ctx, SysArgs* args);
unsigned long handle_close_range(Context* ctx, SysArgs* args);