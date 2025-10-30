#pragma once

#include "base_types.h"
#include "myseccomp.h"

#include <sys/types.h>

struct CallSigprocmask {
    int how;
    const sigset_t* set;
    sigset_t* oldset;
    size_t sigsetsize;
    int* ret;
};
typedef struct CallSigprocmask CallSigprocmask;

struct CallSigaction {
    int signum;
    const struct k_sigaction* act;
    struct k_sigaction* oldact;
    size_t sigsetsize;
    int* ret;
};
typedef struct CallSigaction CallSigaction;

struct CallAccept {
    int is4;
    int fd;
    void* addr;
    int* addrlen;
    int flags;
    int* ret;
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
    int* ret;
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
    uint64_t mask;
    int dirfd;
    const char* path;
    int* ret;
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
    uint64_t mask;
    int* ret;
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
    int* ret;
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

struct CallPtrace {
    long request;
    long pid;
    void* addr;
    void* data;
    long* ret;
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
    int* ret;
};
typedef struct CallKill CallKill;

__attribute__((unused)) static void callkill_copy(CallKill* dst,
                                                  const CallKill* call) {
    dst->pid = call->pid;
    dst->sig = call->sig;
    dst->ret = call->ret;
}

struct CallMisc {
    SysArgs args;
    unsigned long* ret;
};
typedef struct CallMisc CallMisc;

struct CallMmap {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
    unsigned long* ret;
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

enum CloneType {
    CLONETYPE_FORK,
    CLONETYPE_VFORK,
    CLONETYPE_CLONE,
    CLONETYPE_CLONE3
};
typedef CloneType CloneType;

struct CallClone {
    CloneType type;
    struct clone_args* args;
    size_t size;
    int* ret;
};
typedef struct CallClone CallClone;

__attribute__((unused)) static void callclone_copy(CallClone* dst,
                                                   const CallClone* call) {
    dst->type = call->type;
    if (call->type >= CLONETYPE_CLONE) {
        dst->args = call->args;
        dst->size = call->size;
    }
    dst->ret = call->ret;
}

unsigned long handle_rt_sigprocmask(Context* ctx, SysArgs* args);
unsigned long handle_rt_sigaction(Context* ctx, SysArgs* args);
unsigned long handle_accept(Context* ctx, SysArgs* args);
unsigned long handle_accept4(Context* ctx, SysArgs* args);
unsigned long handle_bind(Context* ctx, SysArgs* args);
unsigned long handle_connect(Context* ctx, SysArgs* args);
unsigned long handle_fanotify_mark(Context* ctx, SysArgs* args);
unsigned long handle_inotify_add_watch(Context* ctx, SysArgs* args);
unsigned long handle_getrlimit(Context* ctx, SysArgs* args);
unsigned long handle_setrlimit(Context* ctx, SysArgs* args);
unsigned long handle_prlimit64(Context* ctx, SysArgs* args);
unsigned long handle_ptrace(Context* ctx, SysArgs* args);
unsigned long handle_kill(Context* ctx, SysArgs* args);
unsigned long handle_misc(Context* ctx, SysArgs* args);
unsigned long handle_mmap(Context* ctx, SysArgs* args);
unsigned long handle_fork(Context* ctx, SysArgs* args);
unsigned long handle_vfork(Context* ctx, SysArgs* args);
unsigned long handle_clone(Context* ctx, SysArgs* args);
unsigned long handle_clone3(Context* ctx, SysArgs* args);