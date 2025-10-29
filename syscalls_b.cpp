#include "intercept.h"
#include "syscalls_b.h"
#include "util.h"
#include "signalmanager.h"

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
    CallLink call = {
        .at = 0, .oldpath = oldpath, .newpath = newpath, .ret = &ret};

    _next->link(ctx, _next->link_next, &call);

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
    CallLink call = {.at = 1,
                     .olddirfd = olddirfd,
                     .oldpath = oldpath,
                     .newdirfd = newdirfd,
                     .newpath = newpath,
                     .flags = flags,
                     .ret = &ret};

    _next->link(ctx, _next->link_next, &call);

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
    CallLink call = {
        .at = 0, .oldpath = oldpath, .newpath = newpath, .ret = &ret};

    _next->symlink(ctx, _next->symlink_next, &call);

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
    CallLink call = {.at = 1,
                     .oldpath = oldpath,
                     .newdirfd = newdirfd,
                     .newpath = newpath,
                     .ret = &ret};

    _next->symlink(ctx, _next->symlink_next, &call);

    return ret;
}

unsigned long handle_unlink(Context* ctx, SysArgs* args) {
    const char* pathname = (const char*)args->arg1;
    trace("unlink(%s)\n", or_null(pathname));

    if (!pathname) {
        return -EFAULT;
    }

    int ret = {0};
    CallUnlink call = {.at = 0, .path = pathname, .ret = &ret};

    _next->unlink(ctx, _next->unlink_next, &call);

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
    CallUnlink call = {
        .at = 1, .dirfd = dirfd, .path = pathname, .flags = flags, .ret = &ret};

    _next->unlink(ctx, _next->unlink_next, &call);

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
    CallRename call = {.type = RENAMETYPE_AT,
                       .olddirfd = olddirfd,
                       .oldpath = oldpath,
                       .newdirfd = newdirfd,
                       .newpath = newpath,
                       .ret = &ret};

    _next->rename(ctx, _next->rename_next, &call);

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
    CallRename call = {.type = RENAMETYPE_AT2,
                       .olddirfd = olddirfd,
                       .oldpath = oldpath,
                       .newdirfd = newdirfd,
                       .newpath = newpath,
                       .flags = flags,
                       .ret = &ret};

    _next->rename(ctx, _next->rename_next, &call);

    return ret;
}

unsigned long handle_chdir(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    trace("chdir(%s)\n", or_null(path));

    if (!path) {
        return -EFAULT;
    }

    int ret = {0};
    CallChdir call = {.f = 0, .path = path, .ret = &ret};

    _next->chdir(ctx, _next->chdir_next, &call);

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
    CallChmod call = {
        .type = CHMODTYPE_PLAIN, .path = path, .mode = mode, .ret = &ret};

    _next->chmod(ctx, _next->chmod_next, &call);

    return ret;
}

unsigned long handle_fchmod(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    mode_t mode = args->arg2;
    trace("fchmod(%d)\n", fd);

    int ret = {0};
    CallChmod call = {.type = CHMODTYPE_F, .fd = fd, .mode = mode, .ret = &ret};

    _next->chmod(ctx, _next->chmod_next, &call);

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
    CallChmod call = {.type = CHMODTYPE_AT,
                      .dirfd = dirfd,
                      .path = path,
                      .mode = mode,
                      .ret = &ret};

    _next->chmod(ctx, _next->chmod_next, &call);

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
    CallTruncate call = {.f = 0, .path = path, .length = length, .ret = &ret};

    _next->truncate(ctx, _next->truncate_next, &call);

    return ret;
}

unsigned long handle_ftruncate(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    off_t length = args->arg2;
    trace("ftruncate(%d)\n", fd);

    int ret = {0};
    CallTruncate call = {.f = 1, .fd = fd, .length = length, .ret = &ret};

    _next->truncate(ctx, _next->truncate_next, &call);

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
    CallMkdir call = {.at = 0, .path = path, .mode = mode, .ret = &ret};

    _next->mkdir(ctx, _next->mkdir_next, &call);

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
    CallMkdir call = {
        .at = 1, .dirfd = dirfd, .path = path, .mode = mode, .ret = &ret};

    _next->mkdir(ctx, _next->mkdir_next, &call);

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
    CallMknod call = {
        .at = 0, .path = path, .mode = mode, .dev = dev, .ret = &ret};

    _next->mknod(ctx, _next->mknod_next, &call);

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
    CallMknod call = {.at = 1,
                      .dirfd = dirfd,
                      .path = path,
                      .mode = mode,
                      .dev = dev,
                      .ret = &ret};

    _next->mknod(ctx, _next->mknod_next, &call);

    return ret;
}

static int bottom_link(Context* ctx, const This* data, const CallLink* call) {
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
    return ret;
}

static int bottom_symlink(Context* ctx,
                          const This* data,
                          const CallLink* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_symlinkat(call->oldpath, call->newdirfd, call->newpath);
    } else {
        ret = sys_symlink(call->oldpath, call->newpath);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
    return ret;
}

static int bottom_unlink(Context* ctx,
                         const This* data,
                         const CallUnlink* call) {
    int ret;

    signalmanager_enable_signals(ctx);
    if (call->at) {
        ret = sys_unlinkat(call->dirfd, call->path, call->flags);
    } else {
        ret = sys_unlink(call->path);
    }
    signalmanager_disable_signals(ctx);

    *call->ret = ret;
    return ret;
}

static int bottom_rename(Context* ctx,
                         const This* data,
                         const CallRename* call) {
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
    return ret;
}

static int bottom_chmod(Context* ctx, const This* data, const CallChmod* call) {
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
    return ret;
}

static int bottom_truncate(Context* ctx,
                           const This* data,
                           const CallTruncate* call) {
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
    return ret;
}

static int bottom_mkdir(Context* ctx, const This* data, const CallMkdir* call) {
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
    return ret;
}

static int bottom_mknod(Context* ctx, const This* data, const CallMknod* call) {
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
    return ret;
}

void syscalls_b_fill_bottom(CallHandler* bottom) {
    bottom->link = bottom_link;
    bottom->symlink = bottom_symlink;
    bottom->unlink = bottom_unlink;
    bottom->rename = bottom_rename;
    bottom->chmod = bottom_chmod;
    bottom->truncate = bottom_truncate;
    bottom->mkdir = bottom_mkdir;
    bottom->mknod = bottom_mknod;
}