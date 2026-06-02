
#include "fastpath.h"
#include "workarounds.h"
#include "syscall_log.h"
#include "signalmanager.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    if (getenv("LOADER_BLOCKING_SYSCALLS")) {
        signalmanager_skip_enable_signals(1);
    }
    CallHandler* fastpath = fastpath_init(bottom);
    CallHandler* workarounds = workarounds_init(fastpath);
    CallHandler* logger = syscall_log_init(workarounds);
    return logger;
}
