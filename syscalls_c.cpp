#include "intercept.h"
#include "syscalls_c.h"
#include "util.h"
#include "linux/sched.h"
#include "signalmanager.h"
#include "bottomhandler.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

unsigned long handle_rt_sigprocmask(Context* ctx, SysArgs* args) {
    int how = args->arg1;
    const sigset_t* set = (const sigset_t*)args->arg2;
    sigset_t* oldset = (sigset_t*)args->arg3;
    size_t sigsetsize = args->arg4;
    trace("rt_sigprocmask()\n");

    int ret = {0};
    CallSigprocmask call = {.how = how,
                            .set = set,
                            .oldset = oldset,
                            .sigsetsize = sigsetsize,
                            .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_rt_sigaction(Context* ctx, SysArgs* args) {
    int signum = args->arg1;
    const struct k_sigaction* act = (const struct k_sigaction*)args->arg2;
    struct k_sigaction* oldact = (struct k_sigaction*)args->arg3;
    size_t sigsetsize = args->arg4;
    trace("rt_sigaction(%d)\n", signum);

    int ret = {0};
    CallSigaction call = {.signum = signum,
                          .act = act,
                          .oldact = oldact,
                          .sigsetsize = sigsetsize,
                          .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_accept(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int* addrlen = (int*)args->arg3;
    trace("accept()\n");

    int ret = {0};
    CallAccept call = {
        .is4 = 0, .fd = fd, .addr = addr, .addrlen = addrlen, .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_accept4(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int* addrlen = (int*)args->arg3;
    int flags = args->arg4;
    trace("accept4()\n");

    int ret = {0};
    CallAccept call = {.is4 = 1,
                       .fd = fd,
                       .addr = addr,
                       .addrlen = addrlen,
                       .flags = flags,
                       .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_bind(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int addrlen = args->arg3;
    trace("bind()\n");

    int ret = {0};
    CallConnect call = {
        .is_bind = 1, .fd = fd, .addr = addr, .addrlen = addrlen, .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_connect(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int addrlen = args->arg3;
    trace("connect()\n");

    int ret = {0};
    CallConnect call = {
        .is_bind = 0, .fd = fd, .addr = addr, .addrlen = addrlen, .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fanotify_mark(Context* ctx, SysArgs* args) {
    int fanotify_fd = args->arg1;
    unsigned int flags = args->arg2;
    uint64_t mask = args->arg3;
    int dfd = args->arg4;
    const char* pathname = (const char*)args->arg5;
    trace("fanotify_mark(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    int ret = {0};
    CallFanotifyMark call = {.fd = fanotify_fd,
                             .flags = flags,
                             .mask = mask,
                             .dirfd = dfd,
                             .path = pathname,
                             .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_inotify_add_watch(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* pathname = (const char*)args->arg2;
    uint64_t mask = args->arg3;
    trace("inotify_add_watch(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    int ret = {0};
    CallInotifyAddWatch call = {
        .fd = fd, .path = pathname, .mask = mask, .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_getrlimit(Context* ctx, SysArgs* args) {
    unsigned int resource = args->arg1;
    void* old_rlim = (void*)args->arg2;
    trace("getrlimit()\n");

    int ret = {0};
    CallRlimit call = {.type = RLIMITTYPE_GET,
                       .resource = resource,
                       .old_rlim = old_rlim,
                       .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_setrlimit(Context* ctx, SysArgs* args) {
    unsigned int resource = args->arg1;
    const void* new_rlim = (const void*)args->arg2;
    trace("setrlimit()\n");

    int ret = {0};
    CallRlimit call = {.type = RLIMITTYPE_SET,
                       .resource = resource,
                       .new_rlim = new_rlim,
                       .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_prlimit64(Context* ctx, SysArgs* args) {
    pid_t pid = args->arg1;
    unsigned int resource = args->arg2;
    const void* new_rlim = (const void*)args->arg3;
    void* old_rlim = (void*)args->arg4;
    trace("prlimit64()\n");

    int ret = {0};
    CallRlimit call = {.type = RLIMITTYPE_PR,
                       .pid = pid,
                       .resource = resource,
                       .new_rlim = new_rlim,
                       .old_rlim = old_rlim,
                       .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_ptrace(Context* ctx, SysArgs* args) {
    long request = args->arg1;
    long pid = args->arg2;
    void* addr = (void*)args->arg3;
    void* data = (void*)args->arg4;
    trace("ptrace()\n");

    long ret = {0};
    CallPtrace call = {.request = request,
                       .pid = pid,
                       .addr = addr,
                       .data = data,
                       .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_kill(Context* ctx, SysArgs* args) {
    pid_t pid = args->arg1;
    int sig = args->arg2;
    trace("kill()\n");

    int ret = {0};
    CallKill call = {.pid = pid, .sig = sig, .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_misc(Context* ctx, SysArgs* args) {
    trace("misc(%lu)\n", args->num);

    unsigned long ret = {0};
    CallMisc call = {.args = *args, .ret = &ret};

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mmap(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    unsigned long len = args->arg2;
    unsigned long prot = args->arg3;
    unsigned long flags = args->arg4;
    unsigned long fd = args->arg5;
    unsigned long off = args->arg6;
    trace("mmap()\n");

    unsigned long ret = {0};
    CallMmap call = {
        .addr = addr,
        .len = len,
        .prot = prot,
        .flags = flags,
        .fd = fd,
        .off = off,
        .ret = &ret,
    };

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fork(Context* ctx, SysArgs* args) {
    trace("fork()\n");

    int ret = 0;
    CallClone call = {
        .type = CLONETYPE_FORK,
        .ret = &ret,
    };

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_vfork(Context* ctx, SysArgs* args) {
    trace("vfork()\n");

    int ret = 0;
    CallClone call = {
        .type = CLONETYPE_VFORK,
        .ret = &ret,
    };

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_clone(Context* ctx, SysArgs* args) {
    unsigned long clone_flags = args->arg1;
    unsigned long newsp = args->arg2;
#ifdef __x86_64__
    int* parent_tidptr = (int*)args->arg3;
    unsigned long tls = args->arg5;
    int* child_tidptr = (int*)args->arg4;
#else
    int* parent_tidptr = (int*)args->arg3;
    unsigned long tls = args->arg4;
    int* child_tidptr = (int*)args->arg5;
#endif

    trace("clone()\n");

    struct clone_args cargs = {};
    cargs.flags = clone_flags;
    cargs.stack = newsp;
    cargs.parent_tid = (unsigned long)parent_tidptr;
    cargs.child_tid = (unsigned long)child_tidptr;
    cargs.tls = tls;

    int ret = 0;
    CallClone call = {
        .type = CLONETYPE_CLONE,
        .args = &cargs,
        .size = 64,
        .ret = &ret,
    };

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_clone3(Context* ctx, SysArgs* args) {
    struct clone_args* uargs = (struct clone_args*)args->arg1;
    size_t size = args->arg2;
    trace("clone3()\n");

    int ret = 0;
    CallClone call = {
        .type = CLONETYPE_CLONE3,
        .args = uargs,
        .size = size,
        .ret = &ret,
    };

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

void BottomHandler::next(Context* ctx, const CallAccept* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is4) {
        ret = sys_accept4(call->fd, call->addr, call->addrlen, call->flags);
    } else {
        ret = sys_accept(call->fd, call->addr, call->addrlen);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallConnect* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is_bind) {
        ret = sys_bind(call->fd, call->addr, call->addrlen);
    } else {
        ret = sys_connect(call->fd, call->addr, call->addrlen);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallFanotifyMark* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_fanotify_mark(call->fd, call->flags, call->mask, call->dirfd,
                            call->path);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallInotifyAddWatch* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_inotify_add_watch(call->fd, call->path, call->mask);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallRlimit* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case RLIMITTYPE_GET:
            ret = sys_getrlimit(call->resource, call->old_rlim);
            break;

        case RLIMITTYPE_SET:
            ret = sys_setrlimit(call->resource, call->new_rlim);
            break;

        case RLIMITTYPE_PR:
            ret = sys_prlimit64(call->pid, call->resource,
                                (const rlimit64*)call->new_rlim,
                                (rlimit64*)call->old_rlim);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallPtrace* call) {
    long ret;
    long* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_ptrace(call->request, call->pid, call->addr, call->data);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallKill* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_kill(call->pid, call->sig);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallMisc* call) {
    debug("Unhandled syscall no. %lu\n", call->args.num);

    *call->ret = -ENOSYS;
}

void BottomHandler::next(Context* ctx, const CallMmap* call) {
    unsigned long ret;
    unsigned long* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = (unsigned long)sys_mmap((void*)call->addr, call->len, call->prot,
                                  call->flags, call->fd, call->off);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}