#include "intercept.h"
#include "syscalls_a.h"
#include "util.h"
#include "signalmanager.h"
#include "bottomhandler.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

unsigned long handle_open(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    int flags = args->arg2;
    mode_t mode = args->arg3;
    trace("open(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallOpen call;
    call.at = 0;
    call.path = path;
    call.flags = flags;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_openat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    int flags = args->arg3;
    mode_t mode = args->arg4;
    trace("openat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallOpen call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = path;
    call.flags = flags;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_stat(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    void* statbuf = (void*)args->arg2;
    trace("stat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallStat call;
    call.type = STATTYPE_PLAIN;
    call.path = path;
    call.statbuf = statbuf;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fstat(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* statbuf = (void*)args->arg2;
    trace("fstat()\n");

    int ret = {0};
    CallStat call;
    call.type = STATTYPE_F;
    call.dirfd = fd;
    call.statbuf = statbuf;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_lstat(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    void* statbuf = (void*)args->arg2;
    trace("lstat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallStat call;
    call.type = STATTYPE_L;
    call.path = path;
    call.statbuf = statbuf;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_newfstatat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    void* statbuf = (void*)args->arg3;
    int flags = args->arg4;
    trace("newfstatat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallStat call;
    call.type = STATTYPE_AT;
    call.dirfd = dirfd;
    call.path = path;
    call.flags = flags;
    call.statbuf = statbuf;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_statx(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    int flags = args->arg3;
    unsigned int mask = args->arg4;
    void* statbuf = (void*)args->arg5;
    trace("statx(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallStat call;
    call.type = STATTYPE_X;
    call.dirfd = dirfd;
    call.path = path;
    call.flags = flags;
    call.mask = mask;
    call.statbuf = statbuf;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_readlink(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    char* buf = (char*)args->arg2;
    size_t bufsiz = args->arg3;
    trace("readlink(%s)\n", or_null(path));

    if (!bufsiz) {
        return -EINVAL;
    } else if (!path) {
        return -EFAULT;
    }
    // Not a symlink: -EINVAL
    // buf nullptr: -EFAULT

    ssize_t ret = {0};
    CallReadlink call;
    call.at = 0;
    call.path = path;
    call.buf = buf;
    call.bufsiz = bufsiz;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_readlinkat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    char* buf = (char*)args->arg3;
    size_t bufsiz = args->arg4;
    trace("readlinkat(%s)\n", or_null(path));

    if (!bufsiz) {
        return -EINVAL;
    } else if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallReadlink call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = path;
    call.buf = buf;
    call.bufsiz = bufsiz;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_access(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    int mode = args->arg2;
    trace("access(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallAccess call;
    call.at = 0;
    call.path = path;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_faccessat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    int mode = args->arg3;
    trace("accessat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallAccess call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = path;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_setxattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    const char* name = (const char*)args->arg2;
    const void* value = (const void*)args->arg3;
    size_t size = args->arg4;
    int flags = args->arg5;
    trace("setxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_SET;
    call.type2 = XATTRTYPE_PLAIN;
    call.path = path;
    call.name = name;
    call.value = (void*)value;
    call.size = size;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_lsetxattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    const char* name = (const char*)args->arg2;
    const void* value = (const void*)args->arg3;
    size_t size = args->arg4;
    int flags = args->arg5;
    trace("lsetxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_SET;
    call.type2 = XATTRTYPE_L;
    call.path = path;
    call.name = name;
    call.value = (void*)value;
    call.size = size;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fsetxattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* name = (const char*)args->arg2;
    const void* value = (const void*)args->arg3;
    size_t size = args->arg4;
    int flags = args->arg5;
    trace("fsetxattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_SET;
    call.type2 = XATTRTYPE_F;
    call.fd = fd;
    call.name = name;
    call.value = (void*)value;
    call.size = size;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_getxattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    const char* name = (const char*)args->arg2;
    void* value = (void*)args->arg3;
    size_t size = args->arg4;
    trace("getxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_GET;
    call.type2 = XATTRTYPE_PLAIN;
    call.path = path;
    call.name = name;
    call.value = value;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_lgetxattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    const char* name = (const char*)args->arg2;
    void* value = (void*)args->arg3;
    size_t size = args->arg4;
    trace("lgetxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_GET;
    call.type2 = XATTRTYPE_L;
    call.path = path;
    call.name = name;
    call.value = value;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fgetxattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* name = (const char*)args->arg2;
    void* value = (void*)args->arg3;
    size_t size = args->arg4;
    trace("fgetxattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_GET;
    call.type2 = XATTRTYPE_F;
    call.fd = fd;
    call.name = name;
    call.value = value;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_listxattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    char* list = (char*)args->arg2;
    size_t size = args->arg3;
    trace("listxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_LIST;
    call.type2 = XATTRTYPE_PLAIN;
    call.path = path;
    call.list = list;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_llistxattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    char* list = (char*)args->arg2;
    size_t size = args->arg3;
    trace("llistxattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_LIST;
    call.type2 = XATTRTYPE_L;
    call.path = path;
    call.list = list;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_flistxattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    char* list = (char*)args->arg2;
    size_t size = args->arg3;
    trace("flistxattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_LIST;
    call.type2 = XATTRTYPE_F;
    call.fd = fd;
    call.list = list;
    call.size = size;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_removexattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    const char* name = (const char*)args->arg2;
    trace("removexattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_REMOVE;
    call.type2 = XATTRTYPE_PLAIN;
    call.path = path;
    call.name = name;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_lremovexattr(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    const char* name = (const char*)args->arg2;
    trace("lremovexattr(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_REMOVE;
    call.type2 = XATTRTYPE_L;
    call.path = path;
    call.name = name;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fremovexattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* name = (const char*)args->arg2;
    trace("fremovexattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call;
    call.type = XATTRTYPE_REMOVE;
    call.type2 = XATTRTYPE_F;
    call.fd = fd;
    call.name = name;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fchdir(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    trace("fchdir(%d)\n", fd);

    int ret = {0};
    CallChdir call;
    call.f = 1;
    call.fd = fd;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_getdents(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* dirp = (void*)args->arg2;
    size_t count = args->arg3;
    trace("getdents(%d)\n", fd);

    ssize_t ret = {0};
    CallGetdents call;
    call.is64 = 0;
    call.fd = fd;
    call.dirp = dirp;
    call.count = count;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_getdents64(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* dirp = (void*)args->arg2;
    size_t count = args->arg3;
    trace("getdents64(%d)\n", fd);

    ssize_t ret = {0};
    CallGetdents call;
    call.is64 = 1;
    call.fd = fd;
    call.dirp = dirp;
    call.count = count;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_close(Context* ctx, SysArgs* args) {
    unsigned int fd = args->arg1;
    trace("close(%u)\n", fd);

    int ret = {0};
    CallClose call;
    call.is_range = 0;
    call.fd = fd;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_close_range(Context* ctx, SysArgs* args) {
    unsigned int first = args->arg1;
    unsigned int last = args->arg2;
    unsigned int flags = args->arg3;
    trace("close_range(%u, %u)\n", first, last);

    int ret = {0};
    CallClose call;
    call.is_range = 1;
    call.fd = first;
    call.max_fd = last;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

void BottomHandler::next(Context* ctx, const CallOpen* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_openat(call->dirfd, call->path, call->flags, call->mode);
    } else {
        ret = sys_open(call->path, call->flags, call->mode);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallStat* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case STATTYPE_PLAIN:
            ret = sys_stat(call->path, call->statbuf);
            break;

        case STATTYPE_F:
            ret = sys_fstat(call->dirfd, call->statbuf);
            break;

        case STATTYPE_L:
            ret = sys_lstat(call->path, call->statbuf);
            break;

        case STATTYPE_AT:
            ret = sys_newfstatat(call->dirfd, call->path, call->statbuf,
                                 call->flags);
            break;

        case STATTYPE_X:
            ret = sys_statx(call->dirfd, call->path, call->flags, call->mask,
                            (struct statx*)call->statbuf);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallReadlink* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_readlinkat(call->dirfd, call->path, call->buf, call->bufsiz);
    } else {
        ret = sys_readlink(call->path, call->buf, call->bufsiz);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallAccess* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_faccessat(call->dirfd, call->path, call->mode);
    } else {
        ret = sys_access(call->path, call->mode);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

static void bottom_setxattr(Context* ctx, const CallXattr* call) {
    int ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_setxattr(call->path, call->name, call->value, call->size,
                               call->flags);
            break;

        case XATTRTYPE_L:
            ret = sys_lsetxattr(call->path, call->name, call->value, call->size,
                                call->flags);
            break;

        case XATTRTYPE_F:
            ret = sys_fsetxattr(call->fd, call->name, call->value, call->size,
                                call->flags);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
}

static void bottom_getxattr(Context* ctx, const CallXattr* call) {
    ssize_t ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_getxattr(call->path, call->name, call->value, call->size);
            break;

        case XATTRTYPE_L:
            ret =
                sys_lgetxattr(call->path, call->name, call->value, call->size);
            break;

        case XATTRTYPE_F:
            ret = sys_fgetxattr(call->fd, call->name, call->value, call->size);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
}

static void bottom_listxattr(Context* ctx, const CallXattr* call) {
    ssize_t ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_listxattr(call->path, call->list, call->size);
            break;

        case XATTRTYPE_L:
            ret = sys_llistxattr(call->path, call->list, call->size);
            break;

        case XATTRTYPE_F:
            ret = sys_flistxattr(call->fd, call->list, call->size);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
}

static void bottom_removexattr(Context* ctx, const CallXattr* call) {
    int ret;

    switch (call->type2) {
        case XATTRTYPE_PLAIN:
            ret = sys_removexattr(call->path, call->name);
            break;

        case XATTRTYPE_L:
            ret = sys_lremovexattr(call->path, call->name);
            break;

        case XATTRTYPE_F:
            ret = sys_fremovexattr(call->fd, call->name);
            break;

        default:
            abort();
            break;
    }

    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallXattr* call) {
    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case XATTRTYPE_SET:
            return bottom_setxattr(ctx, call);
            break;

        case XATTRTYPE_GET:
            return bottom_getxattr(ctx, call);
            break;

        case XATTRTYPE_LIST:
            return bottom_listxattr(ctx, call);
            break;

        case XATTRTYPE_REMOVE:
            return bottom_removexattr(ctx, call);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallChdir* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->f) {
        ret = sys_fchdir(call->fd);
    } else {
        ret = sys_chdir(call->path);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallGetdents* call) {
    ssize_t ret;
    ssize_t* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->is64) {
        ret =
            sys_getdents64(call->fd, (linux_dirent64*)call->dirp, call->count);
    } else {
        ret = sys_getdents(call->fd, call->dirp, call->count);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallClose* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->is_range) {
        ret = sys_close_range(call->fd, call->max_fd, call->flags);
    } else {
        ret = sys_close(call->fd);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
}