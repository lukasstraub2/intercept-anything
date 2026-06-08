
#include "workarounds.h"
#include "signalmanager.h"
#include "fastpath.h"
#include "callhandler.h"
#include "util.h"

class PassthroughAll : public CallHandler {
    public:
    PassthroughAll(CallHandler* next) : CallHandler(next) {}
    int get_filter_flags() override;
};

int PassthroughAll::get_filter_flags() {
    int flags = _next->get_filter_flags();
    if (!env_is_true("LOADER_SKIP_FILTER_ALL")) {
        flags |= FILTER_ALL;
    }
    if (env_is_true("LOADER_ENABLE_VDSO")) {
        flags |= FILTER_VDSO;
    }
    return flags;
}

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    if (env_is_true("LOADER_BLOCKING_SYSCALLS") ||
        env_is_true("LOADER_UNSAFE_SIGNAL_HANDLING")) {
        signalmanager_skip_enable_signals(1);
    }
    if (env_is_true("LOADER_UNSAFE_SIGNAL_HANDLING")) {
        intercept_unsafe_signal_handling(1);
    }
    CallHandler* passthrough = new PassthroughAll(bottom);

    CallHandler* fastpath = passthrough;
    if (!env_is_true("LOADER_SKIP_FASTPATH")) {
        fastpath =
            fastpath_init(passthrough, env_is_true("LOADER_ENABLE_VDSO"));
    }
    return workarounds_init(fastpath);
}
