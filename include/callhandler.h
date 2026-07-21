#pragma once

#include "base_types.h"
#include "syscalls_a.h"
#include "syscalls_b.h"
#include "syscalls_c.h"
#include "syscalls_d.h"
#include "syscalls_exec.h"

class ICallHandler {
    public:
    virtual ~ICallHandler() {};

    virtual int get_filter_flags() = 0;
    virtual void next(Context* ctx, const CallOpen* call) = 0;
    virtual void next(Context* ctx, const CallStat* call) = 0;
    virtual void next(Context* ctx, const CallReadlink* call) = 0;
    virtual void next(Context* ctx, const CallAccess* call) = 0;
    virtual void next(Context* ctx, const CallXattr* call) = 0;
    virtual void next(Context* ctx, const CallChdir* call) = 0;
    virtual void next(Context* ctx, const CallGetdents* call) = 0;
    virtual void next(Context* ctx, const CallDup* call) = 0;
    virtual void next(Context* ctx, const CallDup3* call) = 0;
    virtual void next(Context* ctx, const CallFcntl* call) = 0;
    virtual void next(Context* ctx, const CallIoctl* call) = 0;
    virtual void next(Context* ctx, const CallClose* call) = 0;
    virtual void next(Context* ctx, const CallLink* call) = 0;
    virtual void next(Context* ctx, const CallSymlink* call) = 0;
    virtual void next(Context* ctx, const CallUnlink* call) = 0;
    virtual void next(Context* ctx, const CallRename* call) = 0;
    virtual void next(Context* ctx, const CallChmod* call) = 0;
    virtual void next(Context* ctx, const CallTruncate* call) = 0;
    virtual void next(Context* ctx, const CallMkdir* call) = 0;
    virtual void next(Context* ctx, const CallMknod* call) = 0;
    virtual void next(Context* ctx, const CallSigprocmask* call) = 0;
    virtual void next(Context* ctx, const CallSigaction* call) = 0;
    virtual void next(Context* ctx, const CallAccept* call) = 0;
    virtual void next(Context* ctx, const CallConnect* call) = 0;
    virtual void next(Context* ctx, const CallFanotifyMark* call) = 0;
    virtual void next(Context* ctx, const CallInotifyAddWatch* call) = 0;
    virtual void next(Context* ctx, const CallRlimit* call) = 0;
    virtual void next(Context* ctx, const CallPtrace* call) = 0;
    virtual void next(Context* ctx, const CallKill* call) = 0;
    virtual void next(Context* ctx, const CallMisc* call) = 0;
    virtual void next(Context* ctx, const CallMmap* call) = 0;
    virtual void next(Context* ctx, const CallClone* call) = 0;
    virtual void next(Context* ctx, const CallExec* call) = 0;
    virtual void next(Context* ctx, const CallReadWrite* call) = 0;
    virtual void next(Context* ctx, const CallSendfile* call) = 0;
    virtual void next(Context* ctx, const CallSplice* call) = 0;
    virtual void next(Context* ctx, const CallSocket* call) = 0;
    virtual void next(Context* ctx, const CallSendRecv* call) = 0;
    virtual void next(Context* ctx, const CallMsg* call) = 0;
    virtual void next(Context* ctx, const CallShutdown* call) = 0;
    virtual void next(Context* ctx, const CallListen* call) = 0;
    virtual void next(Context* ctx, const CallSockName* call) = 0;
    virtual void next(Context* ctx, const CallSocketpair* call) = 0;
    virtual void next(Context* ctx, const CallSockOpt* call) = 0;
    virtual void next(Context* ctx, const CallSigreturn* call) = 0;
    virtual void next(Context* ctx, const CallMremap* call) = 0;
    virtual void next(Context* ctx, const CallMemop* call) = 0;
    virtual void next(Context* ctx, const CallClockTimeOps* call) = 0;
    virtual void next(Context* ctx, const CallGetcpu* call) = 0;
};

class CallHandler : virtual public ICallHandler {
    protected:
    CallHandler* const _next;

    public:
    CallHandler(CallHandler* next) : _next(next) {}

    void next(Context* ctx, const CallOpen* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallStat* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallReadlink* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallAccess* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallXattr* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallChdir* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallGetdents* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallDup* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallDup3* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallFcntl* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallIoctl* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallClose* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallLink* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSymlink* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallUnlink* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallRename* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallChmod* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallTruncate* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMkdir* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMknod* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSigprocmask* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSigaction* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallAccept* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallConnect* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallFanotifyMark* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallInotifyAddWatch* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallRlimit* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallPtrace* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallKill* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMisc* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMmap* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallClone* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallExec* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallReadWrite* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSendfile* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSplice* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSocket* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSendRecv* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMsg* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallShutdown* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallListen* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSockName* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSocketpair* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSockOpt* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallSigreturn* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMremap* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallMemop* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallClockTimeOps* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    void next(Context* ctx, const CallGetcpu* call) override {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
};