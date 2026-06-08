
#include "fastpath.h"
#include "workarounds.h"
#include "syscall_log.h"
#include "signalmanager.h"
#include "util.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    if (env_is_true("LOADER_BLOCKING_SYSCALLS") ||
        env_is_true("LOADER_UNSAFE_SIGNAL_HANDLING")) {
        signalmanager_skip_enable_signals(1);
    }
    if (env_is_true("LOADER_UNSAFE_SIGNAL_HANDLING")) {
        intercept_unsafe_signal_handling(1);
    }
    CallHandler* fastpath = bottom;
    if (!env_is_true("LOADER_SKIP_FASTPATH")) {
        fastpath = fastpath_init(bottom, env_is_true("LOADER_ENABLE_VDSO"));
    }
    CallHandler* workarounds = workarounds_init(fastpath);
    CallHandler* logger = syscall_log_init(workarounds);
    return logger;
}
