
#include "noxattrs.h"
#include "intercept.h"
#include "callhandler.h"

#include <errno.h>

class NoXattrs : public CallHandler {
    public:
    NoXattrs(CallHandler* next) : CallHandler(next) {}
    void next(Context* ctx, const CallXattr* call) override;
};

void NoXattrs::next(Context* ctx, const CallXattr* call) {
    *call->ret = -EOPNOTSUPP;
}

CallHandler* noxattrs_init(CallHandler* next) {
    return new NoXattrs(next);
}
