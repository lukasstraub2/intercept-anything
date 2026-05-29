
#include "fastpath.h"
#include "workarounds.h"
#include "syscall_log.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    CallHandler* fastpath = fastpath_init(bottom);
    CallHandler* workarounds = workarounds_init(fastpath);
    CallHandler* logger = syscall_log_init(workarounds);
    return logger;
}
