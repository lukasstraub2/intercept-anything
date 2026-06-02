
#include "workarounds.h"
#include "signalmanager.h"
#include "fastpath.h"
#include "callhandler.h"

class PassthroughAll : public CallHandler {
    public:
    PassthroughAll(CallHandler* next) : CallHandler(next) {}
    int get_filter_flags() override;
};

int PassthroughAll::get_filter_flags() {
    return _next->get_filter_flags() | FILTER_ALL;
}

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    if (getenv("LOADER_BLOCKING_SYSCALLS")) {
        signalmanager_skip_enable_signals(1);
    }
    CallHandler* passthrough = new PassthroughAll(bottom);
    CallHandler* fastpath = fastpath_init(passthrough);
    return workarounds_init(fastpath);
}
