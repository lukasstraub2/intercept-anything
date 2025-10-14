
#include "sys.h"
#include "itoa.h"
#include "rootlink.h"
#include "config.h"
#include "intercept.h"
#include "util.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

struct This {
    CallHandler rootlink;
    const CallHandler* next;
};

static int handle_path(const char* path) {
    return !strcmp_prefix(path, "/usr") || !strcmp_prefix(path, "/bin") ||
           !strcmp_prefix(path, "/dev/shm") || !strcmp_prefix(path, "/tmp") ||
           !strcmp_prefix(path, "/lib") || !strcmp_prefix(path, "/lib64") ||
           !strcmp(path, "/etc/nsswitch.conf") ||
           !strcmp(path, "/etc/aliases") || !strcmp(path, "/etc/ethers") ||
           !strcmp(path, "/etc/group") || !strcmp(path, "/etc/hosts") ||
           !strcmp(path, "/etc/netgroup") || !strcmp(path, "/etc/networks") ||
           !strcmp(path, "/etc/passwd") || !strcmp(path, "/etc/protocols") ||
           !strcmp(path, "/etc/publickey") || !strcmp(path, "/etc/rpc") ||
           !strcmp(path, "/etc/services") || !strcmp(path, "/etc/shadow") ||
           !strcmp(path, "/etc/resolv.conf") ||
           !strcmp_prefix(path, "/etc/ssl");
}

static ssize_t mangle_path(char* out, size_t out_len, const char* path) {
    size_t len;

    if (!handle_path(path)) {
        len = strlen(path) + 1;
        if (!out) {
            return len;
        }

        if (len > out_len) {
            return -ENAMETOOLONG;
        }

        memcpy(out, path, len);
        return len;
    }

    len = concat(out, out_len, PREFIX "/tmp/rootlink", path);
    if (!out) {
        if (len > SCRATCH_SIZE) {
            return -ENAMETOOLONG;
        }
        return len;
    }

    if (len > out_len) {
        return -ENAMETOOLONG;
    }

    return len;
}

#define _MANGLE_PATH(__path, errret, prefix)                       \
    ssize_t prefix##len = mangle_path(nullptr, 0, (__path));       \
    if (prefix##len < 0) {                                         \
        call->ret->ret = prefix##len;                              \
        return prefix##len;                                        \
    }                                                              \
                                                                   \
    char prefix##buf[prefix##len];                                 \
    prefix##len = mangle_path(prefix##buf, prefix##len, (__path)); \
    assert(prefix##len >= 0);                                      \
    (__path) = prefix##buf

#define MANGLE_PATH(__path, errret) _MANGLE_PATH(__path, errret, )

static int rootlink_open(Context* ctx,
                         const This* rootlink,
                         const CallOpen* call) {
    CallOpen _call;
    callopen_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->open(ctx, rootlink->next->open_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->open(ctx, rootlink->next->open_next, &_call);
}

static int rootlink_stat(Context* ctx,
                         const This* rootlink,
                         const CallStat* call) {
    CallStat _call;
    callstat_copy(&_call, call);

    if ((stattype_is_at(call->type) && call->path[0] != '/') ||
        call->type == STATTYPE_F) {
        return rootlink->next->stat(ctx, rootlink->next->stat_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->stat(ctx, rootlink->next->stat_next, &_call);
}

static ssize_t rootlink_readlink(Context* ctx,
                                 const This* rootlink,
                                 const CallReadlink* call) {
    CallReadlink _call;
    callreadlink_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->readlink(ctx, rootlink->next->readlink_next,
                                        call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->readlink(ctx, rootlink->next->readlink_next, &_call);
}

static int rootlink_access(Context* ctx,
                           const This* rootlink,
                           const CallAccess* call) {
    CallAccess _call;
    callaccess_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->access(ctx, rootlink->next->access_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->access(ctx, rootlink->next->access_next, &_call);
}

static int rootlink_exec(Context* ctx,
                         const This* rootlink,
                         const CallExec* call) {
    CallExec _call;
    callexec_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->exec(ctx, rootlink->next->exec_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->exec(ctx, rootlink->next->exec_next, &_call);
}

static int rootlink_link(Context* ctx,
                         const This* rootlink,
                         const CallLink* call) {
    CallLink _call;
    calllink_copy(&_call, call);

    _MANGLE_PATH(_call.oldpath, -1, old);
    _MANGLE_PATH(_call.newpath, -1, new);

    if (call->at && call->oldpath[0] != '/') {
        _call.oldpath = call->oldpath;
    }

    if (call->at && call->newpath[0] != '/') {
        _call.newpath = call->newpath;
    }

    return rootlink->next->link(ctx, rootlink->next->link_next, &_call);
}

static int rootlink_symlink(Context* ctx,
                            const This* rootlink,
                            const CallLink* call) {
    CallLink _call;
    calllink_copy(&_call, call);

    _MANGLE_PATH(_call.oldpath, -1, old);
    _MANGLE_PATH(_call.newpath, -1, new);

    if (call->at && call->oldpath[0] != '/') {
        _call.oldpath = call->oldpath;
    }

    if (call->at && call->newpath[0] != '/') {
        _call.newpath = call->newpath;
    }

    return rootlink->next->symlink(ctx, rootlink->next->symlink_next, &_call);
}

static int rootlink_unlink(Context* ctx,
                           const This* rootlink,
                           const CallUnlink* call) {
    CallUnlink _call;
    callunlink_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->unlink(ctx, rootlink->next->unlink_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->unlink(ctx, rootlink->next->unlink_next, &_call);
}

static ssize_t rootlink_xattr(Context* ctx,
                              const This* rootlink,
                              const CallXattr* call) {
    CallXattr _call;
    callxattr_copy(&_call, call);

    if (call->type2 == XATTRTYPE_F) {
        return rootlink->next->xattr(ctx, rootlink->next->xattr_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->xattr(ctx, rootlink->next->xattr_next, &_call);
}

static int rootlink_rename(Context* ctx,
                           const This* rootlink,
                           const CallRename* call) {
    CallRename _call;
    callrename_copy(&_call, call);

    _MANGLE_PATH(_call.oldpath, -1, old);
    _MANGLE_PATH(_call.newpath, -1, new);

    if (renametype_is_at(call->type) && call->oldpath[0] != '/') {
        _call.oldpath = call->oldpath;
    }

    if (renametype_is_at(call->type) && call->newpath[0] != '/') {
        _call.newpath = call->newpath;
    }

    return rootlink->next->rename(ctx, rootlink->next->rename_next, &_call);
}

static int rootlink_chdir(Context* ctx,
                          const This* rootlink,
                          const CallChdir* call) {
    CallChdir _call;
    callchdir_copy(&_call, call);

    if (call->f) {
        return rootlink->next->chdir(ctx, rootlink->next->chdir_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->chdir(ctx, rootlink->next->chdir_next, &_call);
}

static int rootlink_chmod(Context* ctx,
                          const This* rootlink,
                          const CallChmod* call) {
    CallChmod _call;
    callchmod_copy(&_call, call);

    if ((chmodtype_is_at(call->type) && call->path[0] != '/') ||
        call->type == CHMODTYPE_F) {
        return rootlink->next->chmod(ctx, rootlink->next->chmod_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->chmod(ctx, rootlink->next->chmod_next, &_call);
}

static int rootlink_truncate(Context* ctx,
                             const This* rootlink,
                             const CallTruncate* call) {
    CallTruncate _call;
    calltruncate_copy(&_call, call);

    if (call->f) {
        return rootlink->next->truncate(ctx, rootlink->next->truncate_next,
                                        call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->truncate(ctx, rootlink->next->truncate_next, &_call);
}

static int rootlink_mkdir(Context* ctx,
                          const This* rootlink,
                          const CallMkdir* call) {
    CallMkdir _call;
    callmkdir_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->mkdir(ctx, rootlink->next->mkdir_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->mkdir(ctx, rootlink->next->mkdir_next, &_call);
}

static int rootlink_mknod(Context* ctx,
                          const This* rootlink,
                          const CallMknod* call) {
    CallMknod _call;
    callmknod_copy(&_call, call);

    if (call->at && call->path[0] != '/') {
        return rootlink->next->mknod(ctx, rootlink->next->mknod_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->mknod(ctx, rootlink->next->mknod_next, &_call);
}

static int fill_addr_un(struct sockaddr_un* addr, char* sun_path) {
    size_t len = strlen(sun_path) + 1;

    if (len > sizeof(addr->sun_path)) {
        return -ENAMETOOLONG;
    }

    addr->sun_family = AF_UNIX;
    memcpy(addr->sun_path, sun_path, len);

    return 0;
}

static int rootlink_connect(Context* ctx,
                            const This* rootlink,
                            const CallConnect* call) {
    RetInt* _ret = call->ret;
    CallConnect _call;
    callconnect_copy(&_call, call);

    struct sockaddr_storage* generic = (decltype(generic))call->addr;
    if (generic->ss_family == AF_UNIX) {
        struct sockaddr_un* addr = (decltype(addr))call->addr;
        if (addr->sun_path[0] != '\0') {
            // Not an abstract socket
            ssize_t len = mangle_path(nullptr, 0, addr->sun_path);
            if (len < 0) {
                _ret->ret = len;
                return len;
            }

            char new_path[len];
            len = mangle_path(new_path, len, addr->sun_path);
            assert(len >= 0);

            char* slash = strrchr(new_path, '/');
            if (slash) {
                *slash = '\0';
                int dirfd = sys_open(
                    new_path, O_RDONLY | O_DIRECTORY | O_NOCTTY | O_CLOEXEC, 0);
                *slash = '/';
                if (dirfd < 0) {
                    _ret->ret = dirfd;
                    return dirfd;
                }

                char dirfd_buf[21];
                itoa_r(dirfd, dirfd_buf);
                const char* prefix = "/proc/self/fd/";
                const ssize_t prefix_len = strlen(prefix) + 1;
                const char* basename = slash;
                const ssize_t basename_len = strlen(basename) + 1;
                const ssize_t fd_path_len = prefix_len + 21 + basename_len;
                char fd_path[fd_path_len];
                len =
                    concat3(fd_path, fd_path_len, prefix, dirfd_buf, basename);
                if (len > fd_path_len) {
                    abort();
                }

                struct sockaddr_un new_addr;
                int ret = fill_addr_un(&new_addr, fd_path);
                if (ret < 0) {
                    sys_close(dirfd);
                    _ret->ret = ret;
                    return ret;
                }

                _call.addr = &new_addr;
                _call.addrlen = sizeof(new_addr);
                ret = rootlink->next->connect(ctx, rootlink->next->connect_next,
                                              &_call);
                sys_close(dirfd);

                return ret;
            } else {
                struct sockaddr_un new_addr;
                int ret = fill_addr_un(&new_addr, new_path);
                if (ret < 0) {
                    _ret->ret = ret;
                    return ret;
                }

                _call.addr = &new_addr;
                _call.addrlen = sizeof(new_addr);
                return rootlink->next->connect(
                    ctx, rootlink->next->connect_next, &_call);
            }
        }
    }

    return rootlink->next->connect(ctx, rootlink->next->connect_next, call);
}

static int rootlink_fanotify_mark(Context* ctx,
                                  const This* rootlink,
                                  const CallFanotifyMark* call) {
    CallFanotifyMark _call;
    callfanotify_mark_copy(&_call, call);

    if (call->path[0] != '/') {
        return rootlink->next->fanotify_mark(
            ctx, rootlink->next->fanotify_mark_next, call);
    }

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->fanotify_mark(
        ctx, rootlink->next->fanotify_mark_next, &_call);
}

static int rootlink_inotify_add_watch(Context* ctx,
                                      const This* rootlink,
                                      const CallInotifyAddWatch* call) {
    CallInotifyAddWatch _call;
    callinotify_add_watch_copy(&_call, call);

    MANGLE_PATH(_call.path, -1);
    return rootlink->next->inotify_add_watch(
        ctx, rootlink->next->inotify_add_watch_next, &_call);
}

const CallHandler* rootlink_init(const CallHandler* next) {
    static int initialized = 0;
    static This rootlink;

    if (initialized) {
        return nullptr;
    }
    initialized = 1;

    rootlink.next = next;
    rootlink.rootlink = *next;

    rootlink.rootlink.open = rootlink_open;
    rootlink.rootlink.open_next = &rootlink;
    rootlink.rootlink.stat = rootlink_stat;
    rootlink.rootlink.stat_next = &rootlink;
    rootlink.rootlink.readlink = rootlink_readlink;
    rootlink.rootlink.readlink_next = &rootlink;
    rootlink.rootlink.access = rootlink_access;
    rootlink.rootlink.access_next = &rootlink;
    rootlink.rootlink.exec = rootlink_exec;
    rootlink.rootlink.exec_next = &rootlink;
    rootlink.rootlink.link = rootlink_link;
    rootlink.rootlink.link_next = &rootlink;
    rootlink.rootlink.symlink = rootlink_symlink;
    rootlink.rootlink.symlink_next = &rootlink;
    rootlink.rootlink.unlink = rootlink_unlink;
    rootlink.rootlink.unlink_next = &rootlink;
    rootlink.rootlink.xattr = rootlink_xattr;
    rootlink.rootlink.xattr_next = &rootlink;
    rootlink.rootlink.rename = rootlink_rename;
    rootlink.rootlink.rename_next = &rootlink;
    rootlink.rootlink.chdir = rootlink_chdir;
    rootlink.rootlink.chdir_next = &rootlink;
    rootlink.rootlink.chmod = rootlink_chmod;
    rootlink.rootlink.chmod_next = &rootlink;
    rootlink.rootlink.truncate = rootlink_truncate;
    rootlink.rootlink.truncate_next = &rootlink;
    rootlink.rootlink.mkdir = rootlink_mkdir;
    rootlink.rootlink.mkdir_next = &rootlink;
    rootlink.rootlink.mknod = rootlink_mknod;
    rootlink.rootlink.mknod_next = &rootlink;
    rootlink.rootlink.connect = rootlink_connect;
    rootlink.rootlink.connect_next = &rootlink;
    rootlink.rootlink.fanotify_mark = rootlink_fanotify_mark;
    rootlink.rootlink.fanotify_mark_next = &rootlink;
    rootlink.rootlink.inotify_add_watch = rootlink_inotify_add_watch;
    rootlink.rootlink.inotify_add_watch_next = &rootlink;

    return &rootlink.rootlink;
}
