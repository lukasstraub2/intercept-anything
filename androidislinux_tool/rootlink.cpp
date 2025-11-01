
#include "sys.h"
#include "itoa.h"
#include "rootlink.h"
#include "config.h"
#include "intercept.h"
#include "util.h"
#include "callhandler.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

class Rootlink : public CallHandler {
    public:
    Rootlink(CallHandler* next) : CallHandler(next) {}

    void next(Context* ctx, const CallOpen* call) override;
    void next(Context* ctx, const CallStat* call) override;
    void next(Context* ctx, const CallReadlink* call) override;
    void next(Context* ctx, const CallAccess* call) override;
    void next(Context* ctx, const CallXattr* call) override;
    void next(Context* ctx, const CallChdir* call) override;
    void next(Context* ctx, const CallLink* call) override;
    void next(Context* ctx, const CallSymlink* call) override;
    void next(Context* ctx, const CallUnlink* call) override;
    void next(Context* ctx, const CallRename* call) override;
    void next(Context* ctx, const CallChmod* call) override;
    void next(Context* ctx, const CallTruncate* call) override;
    void next(Context* ctx, const CallMkdir* call) override;
    void next(Context* ctx, const CallMknod* call) override;
    void next(Context* ctx, const CallConnect* call) override;
    void next(Context* ctx, const CallFanotifyMark* call) override;
    void next(Context* ctx, const CallInotifyAddWatch* call) override;
    void next(Context* ctx, const CallExec* call) override;
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
        *call->ret = prefix##len;                                  \
        return;                                                    \
    }                                                              \
                                                                   \
    char prefix##buf[prefix##len];                                 \
    prefix##len = mangle_path(prefix##buf, prefix##len, (__path)); \
    assert(prefix##len >= 0);                                      \
    (__path) = prefix##buf

#define MANGLE_PATH(__path, errret) _MANGLE_PATH(__path, errret, )

void Rootlink::next(Context* ctx, const CallOpen* call) {
    CallOpen _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallStat* call) {
    CallStat _call = *call;

    if ((stattype_is_at(call->type) && call->path[0] != '/') ||
        call->type == STATTYPE_F) {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallReadlink* call) {
    CallReadlink _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallAccess* call) {
    CallAccess _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallExec* call) {
    CallExec _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallLink* call) {
    CallLink _call = *call;

    _MANGLE_PATH(_call.oldpath, -1, old);
    _MANGLE_PATH(_call.newpath, -1, new);

    if (call->at && call->oldpath[0] != '/') {
        _call.oldpath = call->oldpath;
    }

    if (call->at && call->newpath[0] != '/') {
        _call.newpath = call->newpath;
    }

    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallSymlink* call) {
    CallSymlink _call = *call;

    _MANGLE_PATH(_call.oldpath, -1, old);
    _MANGLE_PATH(_call.newpath, -1, new);

    if (call->at && call->oldpath[0] != '/') {
        _call.oldpath = call->oldpath;
    }

    if (call->at && call->newpath[0] != '/') {
        _call.newpath = call->newpath;
    }

    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallUnlink* call) {
    CallUnlink _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallXattr* call) {
    CallXattr _call = *call;

    if (call->type2 == XATTRTYPE_F) {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallRename* call) {
    CallRename _call = *call;

    _MANGLE_PATH(_call.oldpath, -1, old);
    _MANGLE_PATH(_call.newpath, -1, new);

    if (renametype_is_at(call->type) && call->oldpath[0] != '/') {
        _call.oldpath = call->oldpath;
    }

    if (renametype_is_at(call->type) && call->newpath[0] != '/') {
        _call.newpath = call->newpath;
    }

    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallChdir* call) {
    CallChdir _call = *call;

    if (call->f) {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallChmod* call) {
    CallChmod _call = *call;

    if ((chmodtype_is_at(call->type) && call->path[0] != '/') ||
        call->type == CHMODTYPE_F) {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallTruncate* call) {
    CallTruncate _call = *call;

    if (call->f) {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallMkdir* call) {
    CallMkdir _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallMknod* call) {
    CallMknod _call = *call;

    if (call->at && call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
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

void Rootlink::next(Context* ctx, const CallConnect* call) {
    int* _ret = call->ret;
    CallConnect _call = *call;

    if (call->get_family() == AF_UNIX) {
        struct sockaddr_un* addr = (decltype(addr))call->addr;
        if (addr->sun_path[0] != '\0') {
            // Not an abstract socket
            ssize_t len = mangle_path(nullptr, 0, addr->sun_path);
            if (len < 0) {
                *_ret = len;
                return;
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
                    *_ret = dirfd;
                    return;
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
                    *_ret = ret;
                    return;
                }

                _call.addr = &new_addr;
                _call.addrlen = sizeof(new_addr);
                _next->next(ctx, &_call);
                ret = *_ret;
                sys_close(dirfd);

                return;
            } else {
                struct sockaddr_un new_addr;
                int ret = fill_addr_un(&new_addr, new_path);
                if (ret < 0) {
                    *_ret = ret;
                    return;
                }

                _call.addr = &new_addr;
                _call.addrlen = sizeof(new_addr);
                return _next->next(ctx, &_call);
            }
        }
    }

    return _next->next(ctx, call);
}

void Rootlink::next(Context* ctx, const CallFanotifyMark* call) {
    CallFanotifyMark _call = *call;

    if (call->path[0] != '/') {
        return _next->next(ctx, call);
    }

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

void Rootlink::next(Context* ctx, const CallInotifyAddWatch* call) {
    CallInotifyAddWatch _call = *call;

    MANGLE_PATH(_call.path, -1);
    return _next->next(ctx, &_call);
}

CallHandler* rootlink_init(CallHandler* next) {
    return new Rootlink(next);
}
