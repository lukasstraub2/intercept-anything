
#include "mysys.h"
#include "workarounds.h"
#include "intercept.h"
#include "linux/ptrace.h"
#include "tls.h"
#include "callhandler.h"
#include "manglepaths.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>

struct Workarounds : public CallHandler {
    public:
    Workarounds(CallHandler* next) : CallHandler(next) {}
    void next(Context* ctx, const CallExec* call) override;
    void next(Context* ctx, const CallPtrace* call) override;
    void next(Context* ctx, const CallKill* call) override;
};

static void rectify_traceme(Tls* tls) {
    long ret = sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (ret < 0) {
        abort();
    }

    __asm volatile("" ::: "memory");
    WRITE_ONCE(tls->workarounds_traceme, 0);
    __asm volatile("" ::: "memory");
}

static void maybe_recitfy_traceme(Tls* tls) {
    if (tls->workarounds_traceme) {
        rectify_traceme(tls);
    }
}

int workarounds_rethrow_signal(Tls* tls, int signum) {
    if (signum == SIGBUS || signum == SIGFPE || signum == SIGILL ||
        signum == SIGSEGV) {
        if (tls->workarounds_traceme) {
            rectify_traceme(tls);

            return 1;
        }
    }

    return 0;
}

void Workarounds::next(Context* ctx, const CallExec* call) {
    if (call->final) {
        maybe_recitfy_traceme(ctx->tls);
    }

    if (call->at && call->path[0] != '/') {
        _next->next(ctx, call);
    }

    if (!strcmp(call->path, "/proc/self/exe")) {
        if (call->at && call->flags & AT_SYMLINK_NOFOLLOW) {
            *call->ret = -ELOOP;
            return;
        }

        CallExec copy = *call;
        copy.path = self_exe;
        _next->next(ctx, &copy);
    }

    return _next->next(ctx, call);
}

// Workaround for gdb when using vfork:
// Delay PTRACE_TRACEME until just before the exec()
void Workarounds::next(Context* ctx, const CallPtrace* call) {
    const char* basename = strrchr(self_exe, '/') + 1;

    if (!strcmp(basename, "gdb") && call->request == PTRACE_TRACEME) {
        WRITE_ONCE(ctx->tls->workarounds_traceme, 1);
        __asm volatile("" ::: "memory");
        *call->ret = 0;
        return;
    }

    return _next->next(ctx, call);
}

void Workarounds::next(Context* ctx, const CallKill* call) {
    maybe_recitfy_traceme(ctx->tls);

    return _next->next(ctx, call);
}

struct WorkaroundPaths : public ManglePaths {
    public:
    WorkaroundPaths(CallHandler* next) : ManglePaths(next) {}

    protected:
    int mangle_path(Context* ctx,
                    ICallPath* copy,
                    const ICallPath* call) override;
    int mangle_path(Context* ctx,
                    ICallPathOpen* copy,
                    const ICallPathOpen* call) override;
    int mangle_path(Context* ctx,
                    ICallPathFanotify* copy,
                    const ICallPathFanotify* call) override;
    int mangle_path(Context* ctx,
                    ICallPathF* copy,
                    const ICallPathF* call) override;
    int mangle_path(Context* ctx,
                    ICallPathDual* copy,
                    const ICallPathDual* call) override;
    int mangle_path(Context* ctx,
                    ICallPathSymlink* copy,
                    const ICallPathSymlink* call) override;
    int mangle_path(Context* ctx,
                    ICallPathConnect* copy,
                    const ICallPathConnect* call) override;
};

class UnlinkSymlink : public IDestroyCB {
    char* path;

    public:
    UnlinkSymlink(char* path) { this->path = strdup(path); }

    ~UnlinkSymlink() {
        sys_unlink(this->path);
        free(this->path);
    }
};

static int _mangle_path(char** out,
                        ICallBase* call,
                        int dirfd,
                        const char* path) {
    if (dirfd != AT_FDCWD && path[0] != '/') {
        *out = nullptr;
        return 0;
    }

    if (!strcmp(path, "/proc/self/exe")) {
        ssize_t len = concat(nullptr, 0, tmpdir, "/workarounds-exe.XXXXXX");
        char* new_path = new char[len];

        ssize_t ret = concat(new_path, len, tmpdir, "/workarounds-exe.XXXXXX");
        if (ret > len) {
            delete[] new_path;
            call->set_return(-ENAMETOOLONG);
            return -1;
        }

        char* xxxxxx = new_path + len - 6 - 1;
        randchar6(xxxxxx);

        ret = sys_symlink(self_exe, new_path);
        if (ret < 0) {
            delete[] new_path;
            call->set_return(ret);
            return -1;
        }

        call->set_destroy_cb(new UnlinkSymlink(new_path));
        *out = new_path;
        return 0;
    } else {
        *out = nullptr;
        return 0;
    }
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

int WorkaroundPaths::mangle_path(Context* ctx,
                                 ICallPath* copy,
                                 const ICallPath* call) {
    if (call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_path())) {
        return 0;
    }

    return _mangle_path(copy);
}

int WorkaroundPaths::mangle_path(Context* ctx,
                                 ICallPathOpen* copy,
                                 const ICallPathOpen* call) {
    return _mangle_path(copy);
}

int WorkaroundPaths::mangle_path(Context* ctx,
                                 ICallPathFanotify* copy,
                                 const ICallPathFanotify* call) {
    if (!call->get_path()) {
        return 0;
    }

    char* out;
    int ret = _mangle_path(&out, copy, call->get_dirfd(), call->get_path());
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_path(out);
    delete[] out;
    return 0;
}

int WorkaroundPaths::mangle_path(Context* ctx,
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

int WorkaroundPaths::mangle_path(Context* ctx,
                                 ICallPathDual* copy,
                                 const ICallPathDual* call) {
    char* oldout = nullptr;
    char* newout = nullptr;
    int ret;

    if (!(call->get_flags() & AT_EMPTY_PATH && !strlen(call->get_old_path()))) {
        ret = _mangle_path(&oldout, copy, call->get_old_dirfd(),
                           call->get_old_path());
        if (ret < 0) {
            return -1;
        }
    }

    ret = _mangle_path(&newout, copy, call->get_new_dirfd(),
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

int WorkaroundPaths::mangle_path(Context* ctx,
                                 ICallPathSymlink* copy,
                                 const ICallPathSymlink* call) {
    char* out;
    int ret =
        _mangle_path(&out, copy, call->get_new_dirfd(), call->get_new_path());
    if (ret < 0) {
        return -1;
    } else if (!out) {
        return 0;
    }

    copy->set_new_path(out);
    delete[] out;
    return 0;
}

int WorkaroundPaths::mangle_path(Context* ctx,
                                 ICallPathConnect* copy,
                                 const ICallPathConnect* call) {
    return 0;
}

CallHandler* workarounds_init(CallHandler* next) {
    CallHandler* workaroundpaths = new WorkaroundPaths(next);
    return new Workarounds(workaroundpaths);
}
