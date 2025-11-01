#include "intercept.h"
#include "syscalls_b.h"
#include "util.h"
#include "signalmanager.h"
#include "bottomhandler.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

unsigned long handle_link(Context* ctx, SysArgs* args) {
    const char* oldpath = (const char*)args->arg1;
    const char* newpath = (const char*)args->arg2;
    trace("link(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallLink call;
    call.at = 0;
    call.oldpath = oldpath;
    call.newpath = newpath;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_linkat(Context* ctx, SysArgs* args) {
    int olddirfd = args->arg1;
    const char* oldpath = (const char*)args->arg2;
    int newdirfd = args->arg3;
    const char* newpath = (const char*)args->arg4;
    int flags = args->arg5;
    trace("linkat(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallLink call;
    call.at = 1;
    call.olddirfd = olddirfd;
    call.oldpath = oldpath;
    call.newdirfd = newdirfd;
    call.newpath = newpath;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_symlink(Context* ctx, SysArgs* args) {
    const char* oldpath = (const char*)args->arg1;
    const char* newpath = (const char*)args->arg2;
    trace("symlink(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallSymlink call;
    call.at = 0;
    call.oldpath = oldpath;
    call.newpath = newpath;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_symlinkat(Context* ctx, SysArgs* args) {
    const char* oldpath = (const char*)args->arg1;
    int newdirfd = args->arg2;
    const char* newpath = (const char*)args->arg3;
    trace("symlinkat(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallSymlink call;
    call.at = 1;
    call.oldpath = oldpath;
    call.newdirfd = newdirfd;
    call.newpath = newpath;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_unlink(Context* ctx, SysArgs* args) {
    const char* pathname = (const char*)args->arg1;
    trace("unlink(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    int ret = {0};
    CallUnlink call;
    call.at = 0;
    call.path = pathname;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_unlinkat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* pathname = (const char*)args->arg2;
    int flags = args->arg3;
    trace("unlinkat(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    int ret = {0};
    CallUnlink call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = pathname;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_rename(Context* ctx, SysArgs* args) {
    const char* oldpath = (const char*)args->arg1;
    const char* newpath = (const char*)args->arg2;
    trace("rename(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallRename call;
    call.type = RENAMETYPE_PLAIN;
    call.oldpath = oldpath;
    call.newpath = newpath;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_renameat(Context* ctx, SysArgs* args) {
    int olddirfd = args->arg1;
    const char* oldpath = (const char*)args->arg2;
    int newdirfd = args->arg3;
    const char* newpath = (const char*)args->arg4;
    trace("renameat(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallRename call;
    call.type = RENAMETYPE_AT;
    call.olddirfd = olddirfd;
    call.oldpath = oldpath;
    call.newdirfd = newdirfd;
    call.newpath = newpath;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_renameat2(Context* ctx, SysArgs* args) {
    int olddirfd = args->arg1;
    const char* oldpath = (const char*)args->arg2;
    int newdirfd = args->arg3;
    const char* newpath = (const char*)args->arg4;
    unsigned int flags = args->arg5;
    trace("renameat2(%s, %s)\n", or_null(oldpath), or_null(newpath));

    if (!oldpath || !newpath) {
        return -EFAULT;
    }

    int ret = {0};
    CallRename call;
    call.type = RENAMETYPE_AT2;
    call.olddirfd = olddirfd;
    call.oldpath = oldpath;
    call.newdirfd = newdirfd;
    call.newpath = newpath;
    call.flags = flags;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_chdir(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    trace("chdir(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallChdir call;
    call.f = 0;
    call.path = path;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_chmod(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    mode_t mode = args->arg2;
    trace("chmod(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallChmod call;
    call.type = CHMODTYPE_PLAIN;
    call.path = path;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fchmod(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    mode_t mode = args->arg2;
    trace("fchmod(%d)\n", fd);

    int ret = {0};
    CallChmod call;
    call.type = CHMODTYPE_F;
    call.fd = fd;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_fchmodat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    mode_t mode = args->arg3;
    trace("fchmodat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallChmod call;
    call.type = CHMODTYPE_AT;
    call.dirfd = dirfd;
    call.path = path;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_truncate(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    off_t length = args->arg2;
    trace("truncate(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallTruncate call;
    call.f = 0;
    call.path = path;
    call.length = length;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_ftruncate(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    off_t length = args->arg2;
    trace("ftruncate(%d)\n", fd);

    int ret = {0};
    CallTruncate call;
    call.f = 1;
    call.fd = fd;
    call.length = length;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mkdir(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    mode_t mode = args->arg2;
    trace("mkdir(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallMkdir call;
    call.at = 0;
    call.path = path;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mkdirat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    mode_t mode = args->arg3;
    trace("mkdirat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallMkdir call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = path;
    call.mode = mode;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mknod(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    mode_t mode = args->arg2;
    unsigned int dev = args->arg3;
    trace("mknod(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallMknod call;
    call.at = 0;
    call.path = path;
    call.mode = mode;
    call.dev = dev;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

unsigned long handle_mknodat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    mode_t mode = args->arg3;
    unsigned int dev = args->arg4;
    trace("mknodat(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallMknod call;
    call.at = 1;
    call.dirfd = dirfd;
    call.path = path;
    call.mode = mode;
    call.dev = dev;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);

    return ret;
}

void BottomHandler::next(Context* ctx, const CallLink* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_linkat(call->olddirfd, call->oldpath, call->newdirfd,
                         call->newpath, call->flags);
    } else {
        ret = sys_link(call->oldpath, call->newpath);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallSymlink* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_symlinkat(call->oldpath, call->newdirfd, call->newpath);
    } else {
        ret = sys_symlink(call->oldpath, call->newpath);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallUnlink* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_unlinkat(call->dirfd, call->path, call->flags);
    } else {
        ret = sys_unlink(call->path);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallRename* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case RENAMETYPE_PLAIN:
            ret = sys_rename(call->oldpath, call->newpath);
            break;

        case RENAMETYPE_AT:
            ret = sys_renameat(call->olddirfd, call->oldpath, call->newdirfd,
                               call->newpath);
            break;

        case RENAMETYPE_AT2:
            ret = sys_renameat2(call->olddirfd, call->oldpath, call->newdirfd,
                                call->newpath, call->flags);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallChmod* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case CHMODTYPE_PLAIN:
            ret = sys_chmod(call->path, call->mode);
            break;

        case CHMODTYPE_F:
            ret = sys_fchmod(call->fd, call->mode);
            break;

        case CHMODTYPE_AT:
            ret = sys_fchmodat(call->dirfd, call->path, call->mode);
            break;

        default:
            abort();
            break;
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallTruncate* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->f) {
        ret = sys_ftruncate(call->fd, call->length);
    } else {
        ret = sys_truncate(call->path, call->length);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallMkdir* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_mkdirat(call->dirfd, call->path, call->mode);
    } else {
        ret = sys_mkdir(call->path, call->mode);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}

void BottomHandler::next(Context* ctx, const CallMknod* call) {
    int ret;
    int* _ret = call->ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_mknodat(call->dirfd, call->path, call->mode, call->dev);
    } else {
        ret = sys_mknod(call->path, call->mode, call->dev);
    }
    signalmanager_disable_signals(ctx);

    *_ret = ret;
}