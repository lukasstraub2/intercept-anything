
#include "noxattrs.h"
#include "intercept.h"
#include "callhandler.h"

#include <errno.h>

class NoXattrs : public CallHandler {
    public:
    NoXattrs(CallHandler* next) : CallHandler(next) {}
    int get_filter_flags() override;
    void next(Context* ctx, const CallXattr* call) override;
};

int NoXattrs::get_filter_flags() {
    return _next->get_filter_flags() | FILTER_FILE;
}

void NoXattrs::next(Context* ctx, const CallXattr* call) {
    *call->ret = -EOPNOTSUPP;
}

CallHandler* noxattrs_init(CallHandler* next) {
    return new NoXattrs(next);
}
