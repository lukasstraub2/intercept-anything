
#include "androidislinux.h"
#include "intercept.h"
#include "callhandler.h"

class AndroidIsLinux : public CallHandler {
    public:
    AndroidIsLinux(CallHandler* next) : CallHandler(next) {}
    void next(Context* ctx, const CallAccept* call);
};

void AndroidIsLinux::next(Context* ctx, const CallAccept* call) {
    CallAccept _call;
    callaccept_copy(&_call, call);

    if (!call->is4) {
        _call.is4 = 1;
        _call.flags = 0;
    }

    return _next->next(ctx, &_call);
}

CallHandler* androidislinux_init(CallHandler* next) {
    return new AndroidIsLinux(next);
}
