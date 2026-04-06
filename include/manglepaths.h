#pragma once

#include "callhandler.h"

class AutoFree {
    public:
    IDestroyCB* cb{};

    ~AutoFree() {
        if (cb) {
            delete cb;
        }
    }
};

class ManglePaths : public CallHandler {
    protected:
    ManglePaths(CallHandler* next) : CallHandler(next){};

    virtual int mangle_path(Context* ctx,
                            ICallPath* copy,
                            const ICallPath* call,
                            IDestroyCB** cb) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathOpen* copy,
                            const ICallPathOpen* call,
                            IDestroyCB** cb) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathFanotify* copy,
                            const ICallPathFanotify* call,
                            IDestroyCB** cb) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathF* copy,
                            const ICallPathF* call,
                            IDestroyCB** cb) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathDual* copy,
                            const ICallPathDual* call,
                            IDestroyCB** cb) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathSymlink* copy,
                            const ICallPathSymlink* call,
                            IDestroyCB** cb) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathConnect* copy,
                            const ICallPathConnect* call,
                            IDestroyCB** cb) = 0;

    void next(Context* ctx, const CallOpen* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallStat* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallReadlink* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallAccess* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallXattr* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallChdir* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallLink* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallSymlink* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallUnlink* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallRename* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallChmod* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallTruncate* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallMkdir* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallMknod* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallConnect* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallFanotifyMark* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallInotifyAddWatch* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallExec* call) override {
        AutoFree cb;
        auto copy = *call;
        if (mangle_path(ctx, &copy, call, &cb.cb)) {
            return;
        }
        _next->next(ctx, &copy);
    }
};