#include "intercept.h"
#include "syscalls_a.h"
#include "util.h"

#define DEBUG_ENV "DEBUG_INTERCEPT"
#include "debug.h"

unsigned long handle_open(Context* ctx, SysArgs* args) {
    const char* path = (const char*)args->arg1;
    int flags = args->arg2;
    mode_t mode = args->arg3;
    trace("open(%s)\n", or_null(path));

    int ret = {0};
    CallOpen call = {
        .at = 0, .path = path, .flags = flags, .mode = mode, .ret = &ret};

    _next->open(ctx, _next->open_next, &call);

    return ret;
}

unsigned long handle_openat(Context* ctx, SysArgs* args) {
    int dirfd = args->arg1;
    const char* path = (const char*)args->arg2;
    int flags = args->arg3;
    mode_t mode = args->arg4;
    trace("openat(%s)\n", or_null(path));

    int ret = {0};
    CallOpen call = {.at = 1,
                     .dirfd = dirfd,
                     .path = path,
                     .flags = flags,
                     .mode = mode,
                     .ret = &ret};

    _next->open(ctx, _next->open_next, &call);

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
    CallStat call = {
        .type = STATTYPE_PLAIN, .path = path, .statbuf = statbuf, .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

    return ret;
}

unsigned long handle_fstat(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* statbuf = (void*)args->arg2;
    trace("fstat()\n");

    int ret = {0};
    CallStat call = {
        .type = STATTYPE_F, .dirfd = fd, .statbuf = statbuf, .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

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
    CallStat call = {
        .type = STATTYPE_L, .path = path, .statbuf = statbuf, .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

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
    CallStat call = {.type = STATTYPE_AT,
                     .dirfd = dirfd,
                     .path = path,
                     .flags = flags,
                     .statbuf = statbuf,
                     .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

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
    CallStat call = {.type = STATTYPE_X,
                     .dirfd = dirfd,
                     .path = path,
                     .flags = flags,
                     .mask = mask,
                     .statbuf = statbuf,
                     .ret = &ret};

    _next->stat(ctx, _next->stat_next, &call);

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
    CallReadlink call = {
        .at = 0, .path = path, .buf = buf, .bufsiz = bufsiz, .ret = &ret};

    _next->readlink(ctx, _next->readlink_next, &call);

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
    CallReadlink call = {.at = 1,
                         .dirfd = dirfd,
                         .path = path,
                         .buf = buf,
                         .bufsiz = bufsiz,
                         .ret = &ret};

    _next->readlink(ctx, _next->readlink_next, &call);

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
    CallAccess call = {.at = 0, .path = path, .mode = mode, .ret = &ret};

    _next->access(ctx, _next->access_next, &call);

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
    CallAccess call = {
        .at = 1, .dirfd = dirfd, .path = path, .mode = mode, .ret = &ret};

    _next->access(ctx, _next->access_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_SET,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .name = name,
                      .value = (void*)value,
                      .size = size,
                      .flags = flags,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_SET,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .name = name,
                      .value = (void*)value,
                      .size = size,
                      .flags = flags,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_SET,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .name = name,
                      .value = (void*)value,
                      .size = size,
                      .flags = flags,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_GET,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .name = name,
                      .value = value,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_GET,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .name = name,
                      .value = value,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret;
}

unsigned long handle_fgetxattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* name = (const char*)args->arg2;
    void* value = (void*)args->arg3;
    size_t size = args->arg4;
    trace("fgetxattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call = {.type = XATTRTYPE_GET,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .name = name,
                      .value = value,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_LIST,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .list = list,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_LIST,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .list = list,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret;
}

unsigned long handle_flistxattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    char* list = (char*)args->arg2;
    size_t size = args->arg3;
    trace("flistxattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call = {.type = XATTRTYPE_LIST,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .list = list,
                      .size = size,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_REMOVE,
                      .type2 = XATTRTYPE_PLAIN,
                      .path = path,
                      .name = name,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallXattr call = {.type = XATTRTYPE_REMOVE,
                      .type2 = XATTRTYPE_L,
                      .path = path,
                      .name = name,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

    return ret;
}

unsigned long handle_fremovexattr(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    const char* name = (const char*)args->arg2;
    trace("fremovexattr(%d)\n", fd);

    ssize_t ret = {0};
    CallXattr call = {.type = XATTRTYPE_REMOVE,
                      .type2 = XATTRTYPE_F,
                      .fd = fd,
                      .name = name,
                      .ret = &ret};

    _next->xattr(ctx, _next->xattr_next, &call);

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
    CallRename call = {.type = RENAMETYPE_PLAIN,
                       .oldpath = oldpath,
                       .newpath = newpath,
                       .ret = &ret};

    _next->rename(ctx, _next->rename_next, &call);

    return ret;
}

unsigned long handle_fchdir(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    trace("fchdir(%d)\n", fd);

    int ret = {0};
    CallChdir call = {.f = 1, .fd = fd, .ret = &ret};

    _next->chdir(ctx, _next->chdir_next, &call);

    return ret;
}

unsigned long handle_getdents(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* dirp = (void*)args->arg2;
    size_t count = args->arg3;
    trace("getdents(%d)\n", fd);

    ssize_t ret = {0};
    CallGetdents call = {
        .is64 = 0, .fd = fd, .dirp = dirp, .count = count, .ret = &ret};

    _next->getdents(ctx, _next->getdents_next, &call);

    return ret;
}

unsigned long handle_getdents64(Context* ctx, SysArgs* args) {
    int fd = args->arg1;
    void* dirp = (void*)args->arg2;
    size_t count = args->arg3;
    trace("getdents64(%d)\n", fd);

    ssize_t ret = {0};
    CallGetdents call = {
        .is64 = 1, .fd = fd, .dirp = dirp, .count = count, .ret = &ret};

    _next->getdents(ctx, _next->getdents_next, &call);

    return ret;
}

unsigned long handle_close(Context* ctx, SysArgs* args) {
    unsigned int fd = args->arg1;
    trace("close(%u)\n", fd);

    int ret = {0};
    CallClose call = {.is_range = 0, .fd = fd, .ret = &ret};

    _next->close(ctx, _next->close_next, &call);

    return ret;
}

unsigned long handle_close_range(Context* ctx, SysArgs* args) {
    unsigned int first = args->arg1;
    unsigned int last = args->arg2;
    unsigned int flags = args->arg3;
    trace("close_range(%u, %u)\n", first, last);

    int ret = {0};
    CallClose call = {.is_range = 1,
                      .fd = first,
                      .max_fd = last,
                      .flags = flags,
                      .ret = &ret};

    _next->close(ctx, _next->close_next, &call);

    return ret;
}