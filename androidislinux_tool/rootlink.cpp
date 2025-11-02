
#include "sys.h"
#include "itoa.h"
#include "rootlink.h"
#include "config.h"
#include "intercept.h"
#include "util.h"
#include "manglepaths.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

class Rootlink final : public ManglePaths {
    public:
    Rootlink(CallHandler* next) : ManglePaths(next) {}

    protected:
    virtual int mangle_path(Context* ctx,
                            ICallPath* copy,
                            const ICallPath* call) override;
    virtual int mangle_path(Context* ctx,
                            ICallPathOpen* copy,
                            const ICallPathOpen* call) override;
    virtual int mangle_path(Context* ctx,
                            ICallPathFanotify* copy,
                            const ICallPathFanotify* call) override;
    virtual int mangle_path(Context* ctx,
                            ICallPathF* copy,
                            const ICallPathF* call) override;
    virtual int mangle_path(Context* ctx,
                            ICallPathDual* copy,
                            const ICallPathDual* call) override;
    virtual int mangle_path(Context* ctx,
                            ICallPathSymlink* copy,
                            const ICallPathSymlink* call) override;
    virtual int mangle_path(Context* ctx,
                            ICallPathConnect* copy,
                            const ICallPathConnect* call) override;
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

static int _mangle_path(char** out,
                        const IReturn* call,
                        int dirfd,
                        const char* path) {
    if (dirfd != AT_FDCWD && path[0] != '/') {
        *out = nullptr;
        return 0;
    }

    if (!handle_path(path)) {
        *out = nullptr;
        return 0;
    }

    ssize_t len = concat(nullptr, 0, PREFIX "/tmp/rootlink", path);
    if (len > SCRATCH_SIZE) {
        call->set_return(-ENAMETOOLONG);
        return -1;
    }

    *out = new char[len];
    ssize_t ret = concat(*out, len, PREFIX "/tmp/rootlink", path);
    if (ret > len) {
        delete[] *out;
        call->set_return(-ENAMETOOLONG);
        return -1;
    }

    return 0;
}

static int _mangle_path(ICallPathBase* copy) {
    char* out;

    int ret = _mangle_path(&out, copy, copy->get_dirfd(), copy->get_path());
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_path(out);
    delete[] out;
    return 0;
}

int Rootlink::mangle_path(Context* ctx,
                          ICallPath* copy,
                          const ICallPath* call) {
    if (call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_path())) {
        return 0;
    }

    return _mangle_path(copy);
}

int Rootlink::mangle_path(Context* ctx,
                          ICallPathOpen* copy,
                          const ICallPathOpen* call) {
    return _mangle_path(copy);
}

int Rootlink::mangle_path(Context* ctx,
                          ICallPathFanotify* copy,
                          const ICallPathFanotify* call) {
    char* out;
    int ret = _mangle_path(&out, call, call->get_dirfd(), call->get_path());
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_path(out);
    delete[] out;
    return 0;
}

int Rootlink::mangle_path(Context* ctx,
                          ICallPathF* copy,
                          const ICallPathF* call) {
    if (call->is_f()) {
        return 0;
    }

    if (call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_path())) {
        return 0;
    }

    return _mangle_path(copy);
}

int Rootlink::mangle_path(Context* ctx,
                          ICallPathDual* copy,
                          const ICallPathDual* call) {
    char* oldout = nullptr;
    char* newout = nullptr;
    int ret;

    if (!(call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_old_path()))) {
        ret = _mangle_path(&oldout, call, call->get_old_dirfd(),
                           call->get_old_path());
        if (ret < 0) {
            return -1;
        }
    }

    ret = _mangle_path(&newout, call, call->get_new_dirfd(),
                       call->get_new_path());
    if (ret < 0) {
        delete[] oldout;
        return -1;
    }

    if (oldout) {
        copy->set_old_path(oldout);
    }
    if (newout) {
        copy->set_new_path(newout);
    }
    delete[] oldout;
    delete[] newout;
    return 0;
}

int Rootlink::mangle_path(Context* ctx,
                          ICallPathSymlink* copy,
                          const ICallPathSymlink* call) {
    char* out;
    int ret =
        _mangle_path(&out, call, call->get_new_dirfd(), call->get_new_path());
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_new_path(out);
    delete[] out;
    return 0;
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

class CloseFd : public IDestroyCB {
    int fd;

    public:
    CloseFd(int fd) { fd = fd; }

    ~CloseFd() { sys_close(fd); }
};

int Rootlink::mangle_path(Context* ctx,
                          ICallPathConnect* copy,
                          const ICallPathConnect* call) {
    if (call->get_family() == AF_UNIX) {
        struct sockaddr_un* addr = (decltype(addr))call->get_addr();
        if (addr->sun_path[0] != '\0') {
            // Not an abstract socket
            char* new_path;
            int ret = _mangle_path(&new_path, call, AT_FDCWD, addr->sun_path);
            if (ret < 0) {
                return -1;
            } else if (!new_path) {
                return 0;
            }

            char* slash = strrchr(new_path, '/');
            if (slash) {
                *slash = '\0';
                int dirfd = sys_open(
                    new_path, O_RDONLY | O_DIRECTORY | O_NOCTTY | O_CLOEXEC, 0);
                *slash = '/';
                if (dirfd < 0) {
                    delete[] new_path;
                    call->set_return(dirfd);
                    return -1;
                }

                char dirfd_buf[21];
                itoa_r(dirfd, dirfd_buf);
                const char* prefix = "/proc/self/fd/";
                const ssize_t prefix_len = strlen(prefix) + 1;
                const char* basename = slash;
                const ssize_t basename_len = strlen(basename) + 1;
                const ssize_t fd_path_len = prefix_len + 21 + basename_len;
                char* fd_path = new char[fd_path_len];
                ssize_t len =
                    concat3(fd_path, fd_path_len, prefix, dirfd_buf, basename);
                if (len > fd_path_len) {
                    abort();
                }

                struct sockaddr_un new_addr;
                int ret = fill_addr_un(&new_addr, fd_path);
                delete[] fd_path;
                delete[] new_path;
                if (ret < 0) {
                    call->set_return(ret);
                    sys_close(dirfd);
                    return -1;
                }

                copy->set_addr(&new_addr, sizeof(new_addr));
                copy->set_destroy_cb(new CloseFd(dirfd));
                return 0;
            } else {
                struct sockaddr_un new_addr;
                int ret = fill_addr_un(&new_addr, new_path);
                delete[] new_path;
                if (ret < 0) {
                    call->set_return(ret);
                    return -1;
                }

                copy->set_addr(&new_addr, sizeof(new_addr));
                return 0;
            }
        }
    }

    return 0;
}

CallHandler* rootlink_init(CallHandler* next) {
    return new Rootlink(next);
}
