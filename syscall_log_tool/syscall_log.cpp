
#include "callhandler.h"
#include "linux/sched.h"
#include "util.h"
#include "syscall_log.h"
#include "intercept.h"

#include <stdarg.h>

class SyscallLog final : public CallHandler {
    private:
    void log(const char* call, const char* format, ...)
        __attribute__((format(printf, 3, 4))) {
        va_list ap;

        fprintf(stderr, "%s(", call);

        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);

        fprintf(stderr, ")\n");
    }

    public:
    SyscallLog(CallHandler* next) : CallHandler(next) {}

    int get_filter_flags() override {
        return _next->get_filter_flags() | FILTER_ALL | FILTER_VDSO;
    }

    void next(Context* ctx, const CallOpen* call) override {
        if (call->at) {
            log("openat", "%d, \"%s\", %u, %o", call->dirfd,
                or_null(call->path), call->flags, call->mode);
        } else {
            log("open", "\"%s\", %u, %o", or_null(call->path), call->flags,
                call->mode);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallStat* call) override {
        switch (call->type) {
            case STATTYPE_PLAIN:
                log("stat", "\"%s\", %p", or_null(call->path), call->statbuf);
                break;

            case STATTYPE_F:
                log("fstat", "%d, %p", call->dirfd, call->statbuf);
                break;

            case STATTYPE_L:
                log("lstat", "\"%s\", %p", or_null(call->path), call->statbuf);
                break;

            case STATTYPE_AT:
                log("newfstatat", "%d, \"%s\", %p, %u", call->dirfd,
                    or_null(call->path), call->statbuf, call->flags);
                break;

            case STATTYPE_X:
                log("statx", "%d, \"%s\", %u, %u, %p", call->dirfd,
                    or_null(call->path), call->flags, call->mask,
                    call->statbuf);
                break;
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallReadlink* call) override {
        if (call->at) {
            log("readlinkat", "%d, \"%s\", %p, %lu", call->dirfd,
                or_null(call->path), call->buf, call->bufsiz);
        } else {
            log("readlink", "\"%s\", %p, %lu", or_null(call->path), call->buf,
                call->bufsiz);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallAccess* call) override {
        if (call->at) {
            log("faccessat", "%d, \"%s\", %u", call->dirfd, or_null(call->path),
                call->mode);
        } else {
            log("access", "\"%s\", %u", or_null(call->path), call->mode);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallXattr* call) override {
        const char* path = or_null(call->path);
        const char* name = or_null(call->name);
        void* value = call->value;
        size_t size = call->size;
        int flags = call->flags;
        int fd = call->fd;

        const char* syscall_name;
        const char* format;

        switch (call->type) {
            case XATTRTYPE_SET:
                switch (call->type2) {
                    case XATTRTYPE_PLAIN:
                        syscall_name = "setxattr";
                        format = "\"%s\", \"%s\", %p, %lu, %u";
                        log(syscall_name, format, path, name, value,
                            (unsigned long)size, (unsigned int)flags);
                        break;
                    case XATTRTYPE_L:
                        syscall_name = "lsetxattr";
                        format = "\"%s\", \"%s\", %p, %lu, %u";
                        log(syscall_name, format, path, name, value,
                            (unsigned long)size, (unsigned int)flags);
                        break;
                    case XATTRTYPE_F:
                        syscall_name = "fsetxattr";
                        format = "%d, \"%s\", %p, %lu, %u";
                        log(syscall_name, format, fd, name, value,
                            (unsigned long)size, (unsigned int)flags);
                        break;
                }
                break;

            case XATTRTYPE_GET:
                switch (call->type2) {
                    case XATTRTYPE_PLAIN:
                        syscall_name = "getxattr";
                        format = "\"%s\", \"%s\", %p, %lu";
                        log(syscall_name, format, path, name, value,
                            (unsigned long)size);
                        break;
                    case XATTRTYPE_L:
                        syscall_name = "lgetxattr";
                        format = "\"%s\", \"%s\", %p, %lu";
                        log(syscall_name, format, path, name, value,
                            (unsigned long)size);
                        break;
                    case XATTRTYPE_F:
                        syscall_name = "fgetxattr";
                        format = "%d, \"%s\", %p, %lu";
                        log(syscall_name, format, fd, name, value,
                            (unsigned long)size);
                        break;
                }
                break;

            case XATTRTYPE_LIST:
                switch (call->type2) {
                    case XATTRTYPE_PLAIN:
                        syscall_name = "listxattr";
                        format = "\"%s\", %p, %lu";
                        log(syscall_name, format, path, call->list,
                            (unsigned long)size);
                        break;
                    case XATTRTYPE_L:
                        syscall_name = "llistxattr";
                        format = "\"%s\", %p, %lu";
                        log(syscall_name, format, path, call->list,
                            (unsigned long)size);
                        break;
                    case XATTRTYPE_F:
                        syscall_name = "flistxattr";
                        format = "%d, %p, %lu";
                        log(syscall_name, format, fd, call->list,
                            (unsigned long)size);
                        break;
                }
                break;

            case XATTRTYPE_REMOVE:
                switch (call->type2) {
                    case XATTRTYPE_PLAIN:
                        syscall_name = "removexattr";
                        format = "\"%s\", \"%s\"";
                        log(syscall_name, format, path, name);
                        break;
                    case XATTRTYPE_L:
                        syscall_name = "lremovexattr";
                        format = "\"%s\", \"%s\"";
                        log(syscall_name, format, path, name);
                        break;
                    case XATTRTYPE_F:
                        syscall_name = "fremovexattr";
                        format = "%d, \"%s\"";
                        log(syscall_name, format, fd, name);
                        break;
                }
                break;
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallChdir* call) override {
        if (call->f) {
            log("fchdir", "%d", call->fd);
        } else {
            log("chdir", "\"%s\"", or_null(call->path));
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallGetdents* call) override {
        if (call->is64) {
            log("getdents64", "%d, %p, %lu", call->fd, call->dirp,
                (unsigned long)call->count);
        } else {
            log("getdents", "%d, %p, %lu", call->fd, call->dirp,
                (unsigned long)call->count);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallClose* call) override {
        if (call->is_range) {
            log("close_range", "%u, %u, %u", call->fd, call->max_fd,
                call->flags);
        } else {
            log("close", "%u", call->fd);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallLink* call) override {
        if (call->at) {
            log("linkat", "%d, \"%s\", %d, \"%s\", %u", call->olddirfd,
                or_null(call->oldpath), call->newdirfd, or_null(call->newpath),
                call->flags);
        } else {
            log("link", "\"%s\", \"%s\"", or_null(call->oldpath),
                or_null(call->newpath));
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallSymlink* call) override {
        const char* oldpath = or_null(call->oldpath);
        const char* newpath = or_null(call->newpath);

        if (call->at) {
            log("symlinkat", "\"%s\", %d, \"%s\"", oldpath, call->newdirfd,
                newpath);
        } else {
            log("symlink", "\"%s\", \"%s\"", oldpath, newpath);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallUnlink* call) override {
        const char* path = or_null(call->path);

        if (call->at) {
            log("unlinkat", "%d, \"%s\", %u", call->dirfd, path, call->flags);
        } else {
            log("unlink", "\"%s\"", path);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallRename* call) override {
        const char* oldpath = or_null(call->oldpath);
        const char* newpath = or_null(call->newpath);

        switch (call->type) {
            case RENAMETYPE_PLAIN:
                log("rename", "\"%s\", \"%s\"", oldpath, newpath);
                break;
            case RENAMETYPE_AT:
                log("renameat", "%d, \"%s\", %d, \"%s\"", call->olddirfd,
                    oldpath, call->newdirfd, newpath);
                break;
            case RENAMETYPE_AT2:
                log("renameat2", "%d, \"%s\", %d, \"%s\", %u", call->olddirfd,
                    oldpath, call->newdirfd, newpath, call->flags);
                break;
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallChmod* call) override {
        const char* path = or_null(call->path);
        mode_t mode = call->mode;

        switch (call->type) {
            case CHMODTYPE_PLAIN:
                log("chmod", "\"%s\", %o", path, mode);
                break;
            case CHMODTYPE_F:
                log("fchmod", "%d, %o", call->fd, mode);
                break;
            case CHMODTYPE_AT:
                log("fchmodat", "%d, \"%s\", %o", call->dirfd, path, mode);
                break;
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallTruncate* call) override {
        off_t length = call->length;

        if (call->f) {
            log("ftruncate", "%d, %lu", call->fd, (unsigned long)length);
        } else {
            log("truncate", "\"%s\", %lu", or_null(call->path),
                (unsigned long)length);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallMkdir* call) override {
        const char* path = or_null(call->path);
        mode_t mode = call->mode;

        if (call->at) {
            log("mkdirat", "%d, \"%s\", %o", call->dirfd, path, mode);
        } else {
            log("mkdir", "\"%s\", %o", path, mode);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallMknod* call) override {
        const char* path = or_null(call->path);
        mode_t mode = call->mode;
        unsigned int dev = call->dev;

        if (call->at) {
            log("mknodat", "%d, \"%s\", %o, %u", call->dirfd, path, mode, dev);
        } else {
            log("mknod", "\"%s\", %o, %u", path, mode, dev);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallSigprocmask* call) override {
        log("rt_sigprocmask", "%d, %p, %p, %lu", call->how, call->set,
            call->oldset, (unsigned long)call->sigsetsize);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallSigaction* call) override {
        log("rt_sigaction", "%d, %p, %p, %lu", call->signum, call->act,
            call->oldact, (unsigned long)call->sigsetsize);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallAccept* call) override {
        if (call->is4) {
            log("accept4", "%d, %p, %p, %u", call->fd, call->addr,
                call->addrlen, (unsigned int)call->flags);
        } else {
            log("accept", "%d, %p, %p", call->fd, call->addr, call->addrlen);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallConnect* call) override {
        if (call->is_bind) {
            log("bind", "%d, %p, %u", call->fd, (void*)call->addr,
                (unsigned int)call->addrlen);
        } else {
            log("connect", "%d, %p, %u", call->fd, (void*)call->addr,
                (unsigned int)call->addrlen);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallFanotifyMark* call) override {
        log("fanotify_mark", "%d, %u, %lu, %u, \"%s\"", call->fd, call->flags,
            (unsigned long)call->mask, (unsigned int)call->get_dirfd(),
            or_null(call->get_path()));
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallInotifyAddWatch* call) override {
        log("inotify_add_watch", "%d, \"%s\", %lu", call->fd,
            or_null(call->get_path()), (unsigned long)call->mask);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallRlimit* call) override {
        switch (call->type) {
            case RLIMITTYPE_GET:
                log("getrlimit", "%u, %p", call->resource, call->old_rlim);
                break;
            case RLIMITTYPE_SET:
                log("setrlimit", "%u, %p", call->resource, call->new_rlim);
                break;
            case RLIMITTYPE_PR:
                log("prlimit64", "%u, %u, %p, %p", (unsigned int)call->pid,
                    call->resource, call->new_rlim, call->old_rlim);
                break;
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallPtrace* call) override {
        log("ptrace", "%lu, %lu, %p, %p", call->request, call->pid, call->addr,
            call->data);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallKill* call) override {
        log("kill", "%u, %u", (unsigned int)call->pid, (unsigned int)call->sig);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallMisc* call) override {
        log("misc", "%lu, %lu", call->args.num, call->args.arg1);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallMmap* call) override {
        log("mmap", "%p, %lu, %lu, %lu, %lu, %lu", (void*)call->addr, call->len,
            call->prot, call->flags, call->fd, call->off);
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallClone* call) override {
        switch (call->type) {
            case CLONETYPE_FORK:
                log("fork", "");
                break;
            case CLONETYPE_VFORK:
                log("vfork", "");
                break;
            case CLONETYPE_CLONE:
                log("clone", "%llu, %p, %p, %p, %p", call->args->flags,
                    (void*)call->args->stack, (void*)call->args->parent_tid,
                    (void*)call->args->child_tid, (void*)call->args->tls);
                break;
            case CLONETYPE_CLONE3:
                log("clone3", "args: %p, size: %lu", call->args,
                    (unsigned long)call->size);
                break;
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallExec* call) override {
        if (call->at) {
            log("execveat", "%d, \"%s\", %p, %p, %u", call->dirfd,
                or_null(call->path), call->argv, call->envp, call->flags);
        } else {
            log("execve", "\"%s\", %p, %p", or_null(call->path), call->argv,
                call->envp);
        }
        return _next->next(ctx, call);
    };

    void next(Context* ctx, const CallReadWrite* call) override {
        const char* syscall_name;

        if (call->is_write) {
            switch (call->type) {
                case READWRITE_PLAIN:
                    syscall_name = "write";
                    log(syscall_name, "%lu, %p, %lu", call->fd,
                        call->iov->iov_base, call->iov->iov_len);
                    break;
                case READWRITE_P64:
                    syscall_name = "pwrite64";
                    log(syscall_name, "%lu, %p, %lu, %lu", call->fd,
                        call->iov->iov_base, call->iov->iov_len, call->pos_l);
                    break;
                case READWRITE_PV:
                    syscall_name = "pwritev";
                    log(syscall_name, "%lu, %p, %lu, %lu, %lu", call->fd,
                        call->iov, call->iovcnt, call->pos_l, call->pos_h);
                    break;
                case READWRITE_PV2:
                    syscall_name = "pwritev2";
                    log(syscall_name, "%lu, %p, %lu, %lu, %lu, %u", call->fd,
                        call->iov, call->iovcnt, call->pos_l, call->pos_h,
                        (unsigned int)call->flags);
                    break;
            }
        } else {
            switch (call->type) {
                case READWRITE_PLAIN:
                    syscall_name = "read";
                    log(syscall_name, "%lu, %p, %lu", call->fd,
                        call->iov->iov_base, call->iov->iov_len);
                    break;
                case READWRITE_P64:
                    syscall_name = "pread64";
                    log(syscall_name, "%lu, %p, %lu, %lu", call->fd,
                        call->iov->iov_base, call->iov->iov_len, call->pos_l);
                    break;
                case READWRITE_PV:
                    syscall_name = "preadv";
                    log(syscall_name, "%lu, %p, %lu, %lu, %lu", call->fd,
                        call->iov, call->iovcnt, call->pos_l, call->pos_h);
                    break;
                case READWRITE_PV2:
                    syscall_name = "preadv2";
                    log(syscall_name, "%lu, %p, %lu, %lu, %lu, %u", call->fd,
                        call->iov, call->iovcnt, call->pos_l, call->pos_h,
                        (unsigned int)call->flags);
                    break;
            }
        }
        return _next->next(ctx, call);
    };
};

CallHandler* syscall_log_init(CallHandler* next) {
    return new SyscallLog(next);
}