
#include "workarounds.h"
#include "signalmanager.h"
#include "fastpath.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    signalmanager_skip_enable_signals(1);
    CallHandler* fastpath = fastpath_init(bottom);
    return workarounds_init(fastpath);
}
