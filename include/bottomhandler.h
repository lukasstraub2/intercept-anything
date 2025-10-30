#pragma once

#include "callhandler.h"

class BottomHandler : public CallHandler {
    public:
    BottomHandler() : CallHandler(nullptr) {}

    void next(Context* ctx, const CallOpen* call);
    void next(Context* ctx, const CallStat* call);
    void next(Context* ctx, const CallReadlink* call);
    void next(Context* ctx, const CallAccess* call);
    void next(Context* ctx, const CallXattr* call);
    void next(Context* ctx, const CallChdir* call);
    void next(Context* ctx, const CallGetdents* call);
    void next(Context* ctx, const CallClose* call);
    void next(Context* ctx, const CallLink* call);
    void next(Context* ctx, const CallSymlink* call);
    void next(Context* ctx, const CallUnlink* call);
    void next(Context* ctx, const CallRename* call);
    void next(Context* ctx, const CallChmod* call);
    void next(Context* ctx, const CallTruncate* call);
    void next(Context* ctx, const CallMkdir* call);
    void next(Context* ctx, const CallMknod* call);
    void next(Context* ctx, const CallAccept* call);
    void next(Context* ctx, const CallConnect* call);
    void next(Context* ctx, const CallFanotifyMark* call);
    void next(Context* ctx, const CallInotifyAddWatch* call);
    void next(Context* ctx, const CallRlimit* call);
    void next(Context* ctx, const CallPtrace* call);
    void next(Context* ctx, const CallKill* call);
    void next(Context* ctx, const CallMisc* call);
    void next(Context* ctx, const CallMmap* call);
    void next(Context* ctx, const CallExec* call);
};