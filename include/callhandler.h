#pragma once

#include "base_types.h"
#include "syscalls_a.h"
#include "syscalls_b.h"
#include "syscalls_c.h"
#include "syscalls_exec.h"

class CallHandler {
    protected:
    CallHandler* const _next;

    public:
    CallHandler(CallHandler* next) : _next(next) {}

    virtual void next(Context* ctx, const CallOpen* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallStat* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallReadlink* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallAccess* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallXattr* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallChdir* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallGetdents* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallClose* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallLink* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallSymlink* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallUnlink* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallRename* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallChmod* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallTruncate* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallMkdir* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallMknod* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallSigprocmask* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallSigaction* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallAccept* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallConnect* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallFanotifyMark* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallInotifyAddWatch* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallRlimit* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallPtrace* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallKill* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallMisc* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallMmap* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallClone* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
    virtual void next(Context* ctx, const CallExec* call) {
        __attribute__((musttail)) return _next->next(ctx, call);
    };
};