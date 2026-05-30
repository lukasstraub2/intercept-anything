
#include "androidislinux.h"
#include "intercept.h"
#include "callhandler.h"

#include <errno.h>

class AndroidIsLinux : public CallHandler {
    public:
    AndroidIsLinux(CallHandler* next) : CallHandler(next) {}
    int get_filter_flags() override;
    void next(Context* ctx, const CallAccept* call) override;
    void next(Context* ctx, const CallMisc* call) override;
};

int AndroidIsLinux::get_filter_flags() {
    return _next->get_filter_flags() | FILTER_SOCKET;
}

void AndroidIsLinux::next(Context* ctx, const CallAccept* call) {
    CallAccept _call = *call;

    if (!call->is4) {
        _call.is4 = 1;
        _call.flags = 0;
    }

    return _next->next(ctx, &_call);
}

void AndroidIsLinux::next(Context* ctx, const CallMisc* call) {
    *call->ret = -ENOSYS;
}

CallHandler* androidislinux_init(CallHandler* next) {
    return new AndroidIsLinux(next);
}
