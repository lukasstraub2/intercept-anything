#include "intercept.h"
#include "syscalls_c.h"
#include "util.h"
#include "linux/sched.h"
#include "signalmanager.h"
#include "bottomhandler.h"
#include "errno.h"
#include "mysys.h"

unsigned long handle_rt_sigprocmask(Context* ctx, SysArgs* args) {
    int how = args->arg1;
    const sigset_t* set = (const sigset_t*)args->arg2;
    sigset_t* oldset = (sigset_t*)args->arg3;
    size_t sigsetsize = args->arg4;

    int ret = {0};
    CallSigprocmask call;
    call.how = how;
    call.set = set;
    call.oldset = oldset;
    call.sigsetsize = sigsetsize;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_rt_sigreturn(Context* ctx, SysArgs* args) {
    CallSigreturn call;
    intercept_entrypoint->next(ctx, &call);

    return 0;
}

unsigned long handle_write(Context* ctx, SysArgs* args) {
    unsigned int fd = args->arg1;
    const char* buf = (const char*)args->arg2;
    size_t count = args->arg3;

    struct iovec iov = {(void*)buf, count};

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_PLAIN;
    call.is_write = 1;
    call.fd = fd;
    call.iov = &iov;
    call.iovcnt = 1;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_writev(Context* ctx, SysArgs* args) {
    unsigned long fd = args->arg1;
    const struct iovec* iov = (const struct iovec*)args->arg2;
    unsigned long iovcnt = args->arg3;

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_V;
    call.is_write = 1;
    call.fd = fd;
    call.iov = iov;
    call.iovcnt = iovcnt;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_pwrite64(Context* ctx, SysArgs* args) {
    unsigned int fd = args->arg1;
    const char* buf = (const char*)args->arg2;
    size_t count = args->arg3;
    loff_t pos = args->arg4;

    struct iovec iov = {(void*)buf, count};

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_P64;
    call.is_write = 1;
    call.fd = fd;
    call.iov = &iov;
    call.iovcnt = 1;
    call.pos_l = pos;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_pwritev(Context* ctx, SysArgs* args) {
    unsigned long fd = args->arg1;
    const struct iovec* iov = (const struct iovec*)args->arg2;
    unsigned long iovcnt = args->arg3;
    unsigned long pos_l = args->arg4;
    unsigned long pos_h = args->arg5;

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_PV;
    call.is_write = 1;
    call.fd = fd;
    call.iov = iov;
    call.iovcnt = iovcnt;
    call.pos_l = pos_l;
    call.pos_h = pos_h;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_pwritev2(Context* ctx, SysArgs* args) {
    unsigned long fd = args->arg1;
    const struct iovec* iov = (const struct iovec*)args->arg2;
    unsigned long iovcnt = args->arg3;
    unsigned long pos_l = args->arg4;
    unsigned long pos_h = args->arg5;
    int flags = args->arg6;

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_PV2;
    call.is_write = 1;
    call.fd = fd;
    call.iov = iov;
    call.iovcnt = iovcnt;
    call.pos_l = pos_l;
    call.pos_h = pos_h;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_rt_sigaction(Context* ctx, SysArgs* args) {
    int signum = args->arg1;
    const struct k_sigaction* act = (const struct k_sigaction*)args->arg2;
    struct k_sigaction* oldact = (struct k_sigaction*)args->arg3;
    size_t sigsetsize = args->arg4;

    int ret = {0};
    CallSigaction call;
    call.signum = signum;
    call.act = act;
    call.oldact = oldact;
    call.sigsetsize = sigsetsize;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_accept(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int* addrlen = (int*)args->arg3;

    int ret = {0};
    CallAccept call;
    call.is4 = 0;
    call.fd = fd;
    call.addr = addr;
    call.addrlen = addrlen;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_accept4(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int* addrlen = (int*)args->arg3;
    int flags = args->arg4;

    int ret = {0};
    CallAccept call;
    call.is4 = 1;
    call.fd = fd;
    call.addr = addr;
    call.addrlen = addrlen;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_bind(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int addrlen = args->arg3;

    int ret = {0};
    CallConnect call;
    call.is_bind = 1;
    call.fd = fd;
    call.addr = addr;
    call.addrlen = addrlen;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_connect(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* addr = (void*)args->arg2;
    int addrlen = args->arg3;

    int ret = {0};
    CallConnect call;
    call.is_bind = 0;
    call.fd = fd;
    call.addr = addr;
    call.addrlen = addrlen;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fanotify_mark(Context* ctx, SysArgs* args) {
    int fanotify_fd = args->arg1;
    unsigned int flags = args->arg2;
    uint64_t mask = args->arg3;
    int dfd = args->arg4;
    const char* pathname = (const char*)args->arg5;

    int ret = {0};
    CallFanotifyMark call;
    call.fd = fanotify_fd;
    call.flags = flags;
    call.mask = mask;
    call.dirfd = dfd;
    call.path = pathname;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_inotify_add_watch(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* pathname = (const char*)args->arg2;
    uint64_t mask = args->arg3;

    if (!pathname) {
        return -EFAULT;
    }

    int ret = {0};
    CallInotifyAddWatch call;
    call.fd = fd;
    call.path = pathname;
    call.mask = mask;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_getrlimit(Context* ctx, SysArgs* args) {
    unsigned int resource = args->arg1;
    void* old_rlim = (void*)args->arg2;

    int ret = {0};
    CallRlimit call;
    call.type = RLIMITTYPE_GET;
    call.resource = resource;
    call.old_rlim = old_rlim;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_setrlimit(Context* ctx, SysArgs* args) {
    unsigned int resource = args->arg1;
    const void* new_rlim = (const void*)args->arg2;

    int ret = {0};
    CallRlimit call;
    call.type = RLIMITTYPE_SET;
    call.resource = resource;
    call.new_rlim = new_rlim;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_prlimit64(Context* ctx, SysArgs* args) {
    pid_t pid = args->arg1;
    unsigned int resource = args->arg2;
    const void* new_rlim = (const void*)args->arg3;
    void* old_rlim = (void*)args->arg4;

    int ret = {0};
    CallRlimit call;
    call.type = RLIMITTYPE_PR;
    call.pid = pid;
    call.resource = resource;
    call.new_rlim = new_rlim;
    call.old_rlim = old_rlim;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_ptrace(Context* ctx, SysArgs* args) {
    long request = args->arg1;
    long pid = args->arg2;
    void* addr = (void*)args->arg3;
    void* data = (void*)args->arg4;

    long ret = {0};
    CallPtrace call;
    call.request = request;
    call.pid = pid;
    call.addr = addr;
    call.data = data;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_kill(Context* ctx, SysArgs* args) {
    pid_t pid = args->arg1;
    int sig = args->arg2;

    int ret = {0};
    CallKill call;
    call.pid = pid;
    call.sig = sig;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_misc(Context* ctx, SysArgs* args) {
    unsigned long ret = {0};
    CallMisc call;
    call.args = *args;
    call.ret = &ret;

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

    unsigned long ret = {0};
    CallMmap call;
    call.addr = addr;
    call.len = len;
    call.prot = prot;
    call.flags = flags;
    call.fd = fd;
    call.off = off;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mremap(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    unsigned long old_len = args->arg2;
    unsigned long new_len = args->arg3;
    unsigned long flags = args->arg4;
    unsigned long new_addr = args->arg5;

    unsigned long ret = {0};
    CallMremap call;
    call.addr = addr;
    call.old_len = old_len;
    call.new_len = new_len;
    call.flags = flags;
    call.new_addr = new_addr;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_munmap(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_UNMAP;
    call.addr = addr;
    call.len = len;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_madvise(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;
    unsigned long flags = args->arg3;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_ADVISE;
    call.addr = addr;
    call.len = len;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mprotect(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;
    unsigned long flags = args->arg3;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_PROTECT;
    call.addr = addr;
    call.len = len;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_msync(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;
    unsigned long flags = args->arg3;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_SYNC;
    call.addr = addr;
    call.len = len;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mlock(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_LOCK;
    call.addr = addr;
    call.len = len;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_munlock(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_UNLOCK;
    call.addr = addr;
    call.len = len;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mlock2(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;
    unsigned long flags = args->arg3;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_LOCK2;
    call.addr = addr;
    call.len = len;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mseal(Context* ctx, SysArgs* args) {
    unsigned long addr = args->arg1;
    size_t len = args->arg2;
    unsigned long flags = args->arg3;

    long ret = {0};
    CallMemop call;
    call.type = MEMOP_SEAL;
    call.addr = addr;
    call.len = len;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fork(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallClone call;
    call.type = CLONETYPE_FORK;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_vfork(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallClone call;
    call.type = CLONETYPE_VFORK;
    call.ret = &ret;

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

    struct clone_args cargs = {};
    cargs.flags = clone_flags;
    cargs.stack = newsp;
    cargs.parent_tid = (unsigned long)parent_tidptr;
    cargs.child_tid = (unsigned long)child_tidptr;
    cargs.tls = tls;

    int ret = 0;
    CallClone call;
    call.type = CLONETYPE_CLONE;
    call.args = &cargs;
    call.size = 64;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_clone3(Context* ctx, SysArgs* args) {
    struct clone_args* uargs = (struct clone_args*)args->arg1;
    size_t size = args->arg2;

    int ret = 0;
    CallClone call;
    call.type = CLONETYPE_CLONE3;
    call.args = uargs;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_read(Context* ctx, SysArgs* args) {
    unsigned int fd = args->arg1;
    char* buf = (char*)args->arg2;
    size_t count = args->arg3;

    struct iovec iov = {buf, count};

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_PLAIN;
    call.fd = fd;
    call.iov = &iov;
    call.iovcnt = 1;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_readv(Context* ctx, SysArgs* args) {
    unsigned long fd = args->arg1;
    const struct iovec* iov = (const struct iovec*)args->arg2;
    unsigned long iovcnt = args->arg3;

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_V;
    call.fd = fd;
    call.iov = iov;
    call.iovcnt = iovcnt;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_pread64(Context* ctx, SysArgs* args) {
    unsigned int fd = args->arg1;
    char* buf = (char*)args->arg2;
    size_t count = args->arg3;
    loff_t pos = args->arg4;

    struct iovec iov = {buf, count};

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_P64;
    call.fd = fd;
    call.iov = &iov;
    call.iovcnt = 1;
    call.pos_l = pos;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_preadv(Context* ctx, SysArgs* args) {
    unsigned long fd = args->arg1;
    const struct iovec* iov = (const struct iovec*)args->arg2;
    unsigned long iovcnt = args->arg3;
    unsigned long pos_l = args->arg4;
    unsigned long pos_h = args->arg5;

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_PV;
    call.fd = fd;
    call.iov = iov;
    call.iovcnt = iovcnt;
    call.pos_l = pos_l;
    call.pos_h = pos_h;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_preadv2(Context* ctx, SysArgs* args) {
    unsigned long fd = args->arg1;
    const struct iovec* iov = (const struct iovec*)args->arg2;
    unsigned long iovcnt = args->arg3;
    unsigned long pos_l = args->arg4;
    unsigned long pos_h = args->arg5;
    int flags = args->arg6;

    ssize_t ret = {0};
    CallReadWrite call;
    call.type = READWRITE_PV2;
    call.fd = fd;
    call.iov = iov;
    call.iovcnt = iovcnt;
    call.pos_l = pos_l;
    call.pos_h = pos_h;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_sendfile(Context* ctx, SysArgs* args) {
    int out_fd = args->arg1;
    int in_fd = args->arg2;
    loff_t* offset = (loff_t*)args->arg3;
    size_t count = args->arg4;

    ssize_t ret = 0;
    CallSendfile call;
    call.out_fd = out_fd;
    call.in_fd = in_fd;
    call.offset = offset;
    call.count = count;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return (unsigned long)ret;
}

unsigned long handle_splice(Context* ctx, SysArgs* args) {
    int fd_in = args->arg1;
    loff_t* off_in = (loff_t*)args->arg2;
    int fd_out = args->arg3;
    loff_t* off_out = (loff_t*)args->arg4;
    size_t len = args->arg5;
    unsigned int flags = args->arg6;

    ssize_t ret = 0;
    CallSplice call;
    call.fd_in = fd_in;
    call.off_in = off_in;
    call.fd_out = fd_out;
    call.off_out = off_out;
    call.len = len;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return (unsigned long)ret;
}

void BottomHandler::next(Context* ctx, const CallSigaction* call) {
    int ret;
    int* _ret = call->ret;
    signalmanager_enable_signals(ctx);
    ret = sys_rt_sigaction(call->signum, call->act, call->oldact,
                           call->sigsetsize);
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallSigprocmask* call) {
    int ret;
    int* _ret = call->ret;
    signalmanager_enable_signals(ctx);
    ret = sys_rt_sigprocmask(call->how, call->set, call->oldset,
                             call->sigsetsize);
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallSigreturn* call) {
    abort();
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
    const SysArgs* args = &call->args;
    signalmanager_enable_signals(ctx);

    *call->ret = my_syscall6(args->num, args->arg1, args->arg2, args->arg3,
                             args->arg4, args->arg5, args->arg6);

    signalmanager_disable_signals(ctx);
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

void BottomHandler::next(Context* ctx, const CallMremap* call) {
    unsigned long ret;
    unsigned long* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = (unsigned long)sys_mremap((void*)call->addr, call->old_len,
                                    call->new_len, call->flags,
                                    (void*)call->new_addr);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallMemop* call) {
    long ret;
    long* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case MEMOP_UNMAP:
            ret = sys_munmap((void*)call->addr, call->len);
            break;

        case MEMOP_ADVISE:
            ret = sys_madvise((void*)call->addr, call->len, call->flags);
            break;

        case MEMOP_PROTECT:
            ret = sys_mprotect((void*)call->addr, call->len, call->flags);
            break;

        case MEMOP_SYNC:
            ret = sys_msync((void*)call->addr, call->len, call->flags);
            break;

        case MEMOP_LOCK:
            ret = sys_mlock((void*)call->addr, call->len);
            break;

        case MEMOP_UNLOCK:
            ret = sys_munlock((void*)call->addr, call->len);
            break;

        case MEMOP_LOCK2:
            ret = sys_mlock2((void*)call->addr, call->len, call->flags);
            break;

        case MEMOP_SEAL:
            ret = sys_mseal((void*)call->addr, call->len, call->flags);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallClone* call) {
    abort();
}

void BottomHandler::next(Context* ctx, const CallReadWrite* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is_write) {
        switch (call->type) {
            case READWRITE_PLAIN:
                ret = sys_write(call->fd, (const char*)call->iov->iov_base,
                                call->iov->iov_len);
                break;

            case READWRITE_V:
                ret = sys_writev(call->fd, call->iov, call->iovcnt);
                break;

            case READWRITE_P64:
                ret = sys_pwrite64(call->fd, (const char*)call->iov->iov_base,
                                   call->iov->iov_len, call->pos_l);
                break;

            case READWRITE_PV:
                ret = sys_pwritev(call->fd, call->iov, call->iovcnt,
                                  call->pos_l, call->pos_h);
                break;

            case READWRITE_PV2:
                ret = sys_pwritev2(call->fd, call->iov, call->iovcnt,
                                   call->pos_l, call->pos_h, call->flags);
                break;

            default:
                abort();
                break;
        }
    } else {
        switch (call->type) {
            case READWRITE_PLAIN:
                ret =
                    sys_read(call->fd, call->iov->iov_base, call->iov->iov_len);
                break;

            case READWRITE_V:
                ret = sys_readv(call->fd, call->iov, call->iovcnt);
                break;

            case READWRITE_P64:
                ret = sys_pread64(call->fd, (char*)call->iov->iov_base,
                                  call->iov->iov_len, call->pos_l);
                break;

            case READWRITE_PV:
                ret = sys_preadv(call->fd, call->iov, call->iovcnt, call->pos_l,
                                 call->pos_h);
                break;

            case READWRITE_PV2:
                ret = sys_preadv2(call->fd, call->iov, call->iovcnt,
                                  call->pos_l, call->pos_h, call->flags);
                break;

            default:
                abort();
                break;
        }
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallSendfile* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_sendfile(call->out_fd, call->in_fd, call->offset, call->count);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallSplice* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    ret = sys_splice(call->fd_in, call->off_in, call->fd_out, call->off_out,
                     call->len, call->flags);
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}
