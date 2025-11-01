
#include "mysys.h"
#include "workarounds.h"
#include "intercept.h"
#include "linux/ptrace.h"
#include "tls.h"
#include "callhandler.h"

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

CallHandler* workarounds_init(CallHandler* next) {
    return new Workarounds(next);
}
