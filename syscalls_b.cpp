#include "intercept.h"
#include "syscalls_b.h"
#include "util.h"

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
