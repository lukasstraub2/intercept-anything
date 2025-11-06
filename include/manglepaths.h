#pragma once

#include "callhandler.h"

class ManglePaths : public CallHandler {
    protected:
    ManglePaths(CallHandler* next) : CallHandler(next){};

    virtual int mangle_path(Context* ctx,
                            ICallPath* copy,
                            const ICallPath* call) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathOpen* copy,
                            const ICallPathOpen* call) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathFanotify* copy,
                            const ICallPathFanotify* call) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathF* copy,
                            const ICallPathF* call) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathDual* copy,
                            const ICallPathDual* call) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathSymlink* copy,
                            const ICallPathSymlink* call) = 0;
    virtual int mangle_path(Context* ctx,
                            ICallPathConnect* copy,
                            const ICallPathConnect* call) = 0;

    void next(Context* ctx, const CallOpen* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallStat* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallReadlink* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallAccess* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallXattr* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallChdir* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallLink* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallSymlink* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallUnlink* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallRename* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallChmod* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallTruncate* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallMkdir* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallMknod* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallConnect* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallFanotifyMark* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallInotifyAddWatch* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }

    void next(Context* ctx, const CallExec* call) override {
        auto copy = *call;
        if (mangle_path(ctx, &copy, call)) {
            return;
        }
        _next->next(ctx, &copy);
    }
};