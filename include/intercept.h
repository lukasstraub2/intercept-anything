#pragma once

#include "mynolibc.h"
#include "tls.h"
#include "config.h"
#include "myseccomp.h"

struct Context {
    Tls* tls;
    void* ucontext;
    int signalmanager_masked;
};
typedef struct Context Context;

struct RetInt {
    int ret;
};
typedef struct RetInt RetInt;

struct CallOpen {
    int at;
    int dirfd;
    const char* path;
    int flags;
    mode_t mode;
    RetInt* ret;
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
    RetInt* ret;
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

struct RetSSize {
    ssize_t ret;
};
typedef struct RetSSize RetSSize;

struct CallReadlink {
    int at;
    int dirfd;
    const char* path;
    char* buf;
    size_t bufsiz;
    RetSSize* ret;
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
    RetInt* ret;
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

struct CallExec {
    int at;
    int final;
    int dirfd;
    const char* path;
    char* const* argv;
    char* const* envp;
    int flags;
    RetInt* ret;
};
typedef struct CallExec CallExec;

__attribute__((unused)) static void callexec_copy(CallExec* dst,
                                                  const CallExec* call) {
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

struct CallLink {
    int at;
    int olddirfd;
    const char* oldpath;
    int newdirfd;
    const char* newpath;
    int flags;
    RetInt* ret;
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
    RetInt* ret;
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
    RetSSize* ret;
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
    RetInt* ret;
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

struct CallChdir {
    int f;
    int fd;
    const char* path;
    RetInt* ret;
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
    RetInt* ret;
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
    RetInt* ret;
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
    RetInt* ret;
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

struct CallGetdents {
    int is64;
    int fd;
    void* dirp;
    size_t count;
    RetSSize* ret;
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

struct CallMknod {
    int at;     // Indicates if dirfd is used (1) or not (0)
    int dirfd;  // File descriptor of the directory (if at == 1)
    const char* path;
    mode_t mode;
    unsigned int dev;  // Device number
    RetInt* ret;
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

struct CallAccept {
    int is4;
    int fd;
    void* addr;
    int* addrlen;
    int flags;
    RetInt* ret;
};
typedef struct CallAccept CallAccept;

__attribute__((unused)) static void callaccept_copy(CallAccept* dst,
                                                    const CallAccept* call) {
    dst->is4 = call->is4;
    dst->fd = call->fd;
    dst->addr = call->addr;
    dst->addrlen = call->addrlen;
    if (call->is4) {
        dst->flags = call->flags;
    }
    dst->ret = call->ret;
}

struct CallConnect {
    int is_bind;
    int fd;
    void* addr;
    int addrlen;
    RetInt* ret;
};
typedef struct CallConnect CallConnect;

__attribute__((unused)) static void callconnect_copy(CallConnect* dst,
                                                     const CallConnect* call) {
    dst->is_bind = call->is_bind;
    dst->fd = call->fd;
    dst->addr = call->addr;
    dst->addrlen = call->addrlen;
    dst->ret = call->ret;
}

struct CallFanotifyMark {
    int fd;
    unsigned int flags;
    __u64 mask;
    int dirfd;
    const char* path;
    RetInt* ret;
};
typedef struct CallFanotifyMark CallFanotifyMark;

__attribute__((unused)) static void callfanotify_mark_copy(
    CallFanotifyMark* dst,
    const CallFanotifyMark* call) {
    dst->fd = call->fd;
    dst->flags = call->flags;
    dst->mask = call->mask;
    dst->dirfd = call->dirfd;
    dst->path = call->path;
    dst->ret = call->ret;
}

struct CallInotifyAddWatch {
    int fd;
    const char* path;
    __u32 mask;
    RetInt* ret;
};
typedef struct CallInotifyAddWatch CallInotifyAddWatch;

__attribute__((unused)) static void callinotify_add_watch_copy(
    CallInotifyAddWatch* dst,
    const CallInotifyAddWatch* call) {
    dst->fd = call->fd;
    dst->path = call->path;
    dst->mask = call->mask;
    dst->ret = call->ret;
}

enum RlimitType { RLIMITTYPE_GET, RLIMITTYPE_SET, RLIMITTYPE_PR };
typedef enum RlimitType RlimitType;

struct CallRlimit {
    RlimitType type;
    pid_t pid;
    unsigned int resource;
    const void* new_rlim;
    void* old_rlim;
    RetInt* ret;
};
typedef struct CallRlimit CallRlimit;

__attribute__((unused)) static void callrlimit_copy(CallRlimit* dst,
                                                    const CallRlimit* call) {
    dst->type = call->type;

    if (call->type == RLIMITTYPE_PR) {
        dst->pid = call->pid;
    }

    dst->resource = call->resource;

    if (call->type == RLIMITTYPE_PR || call->type == RLIMITTYPE_SET) {
        dst->new_rlim = call->new_rlim;
    }

    if (call->type == RLIMITTYPE_PR || call->type == RLIMITTYPE_GET) {
        dst->old_rlim = call->old_rlim;
    }

    dst->ret = call->ret;
}

struct CallSigprocmask {
    int how;
    const sigset_t* set;
    sigset_t* oldset;
    size_t sigsetsize;
    RetInt* ret;
};
typedef struct CallSigprocmask CallSigprocmask;

struct CallSigaction {
    int signum;
    const struct sigaction* act;
    struct sigaction* oldact;
    size_t sigsetsize;
    RetInt* ret;
};
typedef struct CallSigaction CallSigaction;

struct RetLong {
    long ret;
};
typedef struct RetLong RetLong;

struct CallPtrace {
    long request;
    long pid;
    void* addr;
    void* data;
    RetLong* ret;
};
typedef struct CallPtrace CallPtrace;

__attribute__((unused)) static void callptrace_copy(CallPtrace* dst,
                                                    const CallPtrace* call) {
    dst->request = call->request;
    dst->pid = call->pid;
    dst->addr = call->addr;
    dst->data = call->data;
    dst->ret = call->ret;
}

struct CallKill {
    pid_t pid;
    int sig;
    RetInt* ret;
};
typedef struct CallKill CallKill;

__attribute__((unused)) static void callkill_copy(CallKill* dst,
                                                  const CallKill* call) {
    dst->pid = call->pid;
    dst->sig = call->sig;
    dst->ret = call->ret;
}

struct CallClose {
    int is_range;
    unsigned int fd;
    unsigned int max_fd;  // Only used for close_range
    unsigned int flags;   // Only used for close_range
    RetInt* ret;
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

struct RetUL {
    unsigned long ret;
};
typedef struct RetUL RetUL;

struct CallMisc {
    SysArgs args;
    RetUL* ret;
};
typedef struct CallMisc CallMisc;

struct CallMmap {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
    RetUL* ret;
};
typedef struct CallMmap CallMmap;

__attribute__((unused)) static void callmmap_copy(CallMmap* dst,
                                                  const CallMmap* call) {
    dst->addr = call->addr;
    dst->len = call->len;
    dst->prot = call->prot;
    dst->flags = call->flags;
    dst->fd = call->fd;
    dst->off = call->off;
    dst->ret = call->ret;
}

typedef struct This This;

// clang-format off
struct CallHandler {
	int (*open)(Context *ctx, const This *data, const CallOpen *call);
	const This *open_next;
	int (*stat)(Context *ctx, const This *data, const CallStat *call);
	const This *stat_next;
	ssize_t (*readlink)(Context *ctx, const This *data, const CallReadlink *call);
	const This *readlink_next;
	int (*access)(Context *ctx, const This *data, const CallAccess *call);
	const This *access_next;
	int (*exec)(Context *ctx, const This *data, const CallExec *call);
	const This *exec_next;
	int (*link)(Context *ctx, const This *data, const CallLink *call);
	const This *link_next;
	int (*symlink)(Context *ctx, const This *data, const CallLink *call);
	const This *symlink_next;
	int (*unlink)(Context *ctx, const This *data, const CallUnlink *call);
	const This *unlink_next;
	ssize_t (*xattr)(Context *ctx, const This *data, const CallXattr *call);
	const This *xattr_next;
	int (*rename)(Context *ctx, const This *data, const CallRename *call);
	const This *rename_next;
	int (*chdir)(Context *ctx, const This *data, const CallChdir *call);
	const This *chdir_next;
	int (*chmod)(Context *ctx, const This *data, const CallChmod *call);
	const This *chmod_next;
	int (*truncate)(Context *ctx, const This *data, const CallTruncate *call);
	const This *truncate_next;
	int (*mkdir)(Context *ctx, const This *data, const CallMkdir *call);
	const This *mkdir_next;
	ssize_t (*getdents)(Context *ctx, const This *data, const CallGetdents *call);
	const This *getdents_next;
	int (*mknod)(Context *ctx, const This *data, const CallMknod *call);
	const This *mknod_next;
	int (*accept)(Context *ctx, const This *data, const CallAccept *call);
	const This *accept_next;
	int (*connect)(Context *ctx, const This *data, const CallConnect *call);
	const This *connect_next;
	int (*fanotify_mark)(Context *ctx, const This *data, const CallFanotifyMark *call);
	const This *fanotify_mark_next;
	int (*inotify_add_watch)(Context *ctx, const This *data, const CallInotifyAddWatch *call);
	const This *inotify_add_watch_next;
	int (*rlimit)(Context *ctx, const This *data, const CallRlimit *call);
	const This *rlimit_next;
	int (*sigprocmask)(Context *ctx, const This *data, const CallSigprocmask *call);
	const This *sigprocmask_next;
	int (*sigaction)(Context *ctx, const This *data, const CallSigaction *call);
	const This *sigaction_next;
	long (*ptrace)(Context *ctx, const This *data, const CallPtrace *call);
	const This *ptrace_next;
	int (*kill)(Context *ctx, const This *data, const CallKill *call);
	const This *kill_next;
	int (*close)(Context *ctx, const This *data, const CallClose *call);
	const This *close_next;
	unsigned long (*misc)(Context *ctx, const This *data, const CallMisc *call);
	const This *misc_next;
	unsigned long (*mmap)(Context *ctx, const This *data, const CallMmap *call);
	const This *mmap_next;
};
// clang-format on

typedef struct CallHandler CallHandler;

extern const char* self_exe;
extern size_t page_size;

void intercept_init(int recursing, const char* exe);
const CallHandler* main_init(const CallHandler* bottom, int recursing);

int pc_in_our_code(void* ucontext);
