
#include "workarounds.h"
#include "syscall_log.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    CallHandler* workarounds = workarounds_init(bottom);
    CallHandler* logger = syscall_log_init(workarounds);
    return logger;
}
