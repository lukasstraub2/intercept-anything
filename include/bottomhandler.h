#pragma once

#include "callhandler.h"
#include "intercept.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winaccessible-base"
class BottomHandler : public CallHandler, public ICallHandler {
    public:
    BottomHandler() : CallHandler(nullptr) {}

    int get_filter_flags() override {
        // For execve
        return FILTER_FILE;
    };
    void next(Context* ctx, const CallOpen* call) override;
    void next(Context* ctx, const CallStat* call) override;
    void next(Context* ctx, const CallReadlink* call) override;
    void next(Context* ctx, const CallAccess* call) override;
    void next(Context* ctx, const CallXattr* call) override;
    void next(Context* ctx, const CallChdir* call) override;
    void next(Context* ctx, const CallGetdents* call) override;
    void next(Context* ctx, const CallClose* call) override;
    void next(Context* ctx, const CallLink* call) override;
    void next(Context* ctx, const CallSymlink* call) override;
    void next(Context* ctx, const CallUnlink* call) override;
    void next(Context* ctx, const CallRename* call) override;
    void next(Context* ctx, const CallChmod* call) override;
    void next(Context* ctx, const CallTruncate* call) override;
    void next(Context* ctx, const CallMkdir* call) override;
    void next(Context* ctx, const CallMknod* call) override;
    void next(Context* ctx, const CallSigprocmask* call) override;
    void next(Context* ctx, const CallSigaction* call) override;
    void next(Context* ctx, const CallAccept* call) override;
    void next(Context* ctx, const CallConnect* call) override;
    void next(Context* ctx, const CallFanotifyMark* call) override;
    void next(Context* ctx, const CallInotifyAddWatch* call) override;
    void next(Context* ctx, const CallRlimit* call) override;
    void next(Context* ctx, const CallPtrace* call) override;
    void next(Context* ctx, const CallKill* call) override;
    void next(Context* ctx, const CallMisc* call) override;
    void next(Context* ctx, const CallMmap* call) override;
    void next(Context* ctx, const CallClone* call) override;
    void next(Context* ctx, const CallExec* call) override;
    void next(Context* ctx, const CallReadWrite* call) override;
    void next(Context* ctx, const CallSocket* call) override;
    void next(Context* ctx, const CallSendRecv* call) override;
    void next(Context* ctx, const CallMsg* call) override;
    void next(Context* ctx, const CallShutdown* call) override;
    void next(Context* ctx, const CallListen* call) override;
    void next(Context* ctx, const CallSockName* call) override;
    void next(Context* ctx, const CallSocketpair* call) override;
    void next(Context* ctx, const CallSockOpt* call) override;
};
#pragma GCC diagnostic pop