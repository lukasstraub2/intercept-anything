#include "intercept.h"
#include "syscalls_d.h"
#include "util.h"
#include "signalmanager.h"
#include "bottomhandler.h"
#include "errno.h"
#include "mysys.h"

unsigned long handle_socket(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallSocket call;
    call.family = (int)args->arg1;
    call.type = (int)args->arg2;
    call.protocol = (int)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_sendto(Context* ctx, SysArgs* args) {
    int ret = 0;
    int len = (int)args->arg6;
    CallSendRecv call;
    call.type = SENDRECV_SENDTO;
    call.fd = (int)args->arg1;
    call.buff = (void*)args->arg2;
    call.len = (size_t)args->arg3;
    call.flags = (unsigned int)args->arg4;
    call.addr = (void*)args->arg5;
    call.addr_len = &len;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_recvfrom(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallSendRecv call;
    call.type = SENDRECV_RECVFROM;
    call.fd = (int)args->arg1;
    call.buff = (void*)args->arg2;
    call.len = (size_t)args->arg3;
    call.flags = (unsigned int)args->arg4;
    call.addr = (void*)args->arg5;
    call.addr_len = (int*)args->arg6;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_sendmsg(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallMsg call;
    call.type = MSG_SEND;
    call.fd = (int)args->arg1;
    call.msg = (void*)args->arg2;
    call.flags = (unsigned int)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_recvmsg(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallMsg call;
    call.type = MSG_RECV;
    call.fd = (int)args->arg1;
    call.msg = (void*)args->arg2;
    call.flags = (unsigned int)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_sendmmsg(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallMsg call;
    call.type = MSG_SENDM;
    call.fd = (int)args->arg1;
    call.msg = (void*)args->arg2;
    call.vlen = (unsigned int)args->arg3;
    call.flags = (unsigned int)args->arg4;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_recvmmsg(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallMsg call;
    call.type = MSG_RECVM;
    call.fd = (int)args->arg1;
    call.msg = (void*)args->arg2;
    call.vlen = (unsigned int)args->arg3;
    call.flags = (unsigned int)args->arg4;
    call.timeout = (struct __kernel_timespec*)args->arg5;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_shutdown(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallShutdown call;
    call.fd = (int)args->arg1;
    call.how = (int)args->arg2;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_listen(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallListen call;
    call.fd = (int)args->arg1;
    call.backlog = (int)args->arg2;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_getsockname(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallSockName call;
    call.type = SOCKNAME_GET;
    call.fd = (int)args->arg1;
    call.usockaddr = (void*)args->arg2;
    call.usockaddr_len = (int*)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_getpeername(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallSockName call;
    call.type = SOCKNAME_PEER;
    call.fd = (int)args->arg1;
    call.usockaddr = (void*)args->arg2;
    call.usockaddr_len = (int*)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_socketpair(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallSocketpair call;
    call.family = (int)args->arg1;
    call.type = (int)args->arg2;
    call.protocol = (int)args->arg3;
    call.usockvec = (int*)args->arg4;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_setsockopt(Context* ctx, SysArgs* args) {
    int ret = 0;
    int len = (int)args->arg5;
    ;
    CallSockOpt call;
    call.type = SOCKOPT_SET;
    call.fd = (int)args->arg1;
    call.level = (int)args->arg2;
    call.optname = (int)args->arg3;
    call.optval = (void*)args->arg4;
    call.optlen = &len;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_getsockopt(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallSockOpt call;
    call.type = SOCKOPT_GET;
    call.fd = (int)args->arg1;
    call.level = (int)args->arg2;
    call.optname = (int)args->arg3;
    call.optval = (void*)args->arg4;
    call.optlen = (int*)args->arg5;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

void BottomHandler::next(Context* ctx, const CallSocket* call) {
    signalmanager_enable_signals(ctx);
    *call->ret = sys_socket(call->family, call->type, call->protocol);
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallSendRecv* call) {
    int ret;
    signalmanager_enable_signals(ctx);
    if (call->type == SENDRECV_SENDTO) {
        ret = sys_sendto(call->fd, call->buff, call->len, call->flags,
                         call->addr, *call->addr_len);
    } else {
        ret = sys_recvfrom(call->fd, call->buff, call->len, call->flags,
                           call->addr, call->addr_len);
    }
    signalmanager_disable_signals(ctx);
    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallMsg* call) {
    long ret;
    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case MSG_SEND:
            ret = sys_sendmsg(call->fd, (struct user_msghdr*)call->msg,
                              call->flags);
            break;
        case MSG_RECV:
            ret = sys_recvmsg(call->fd, (struct user_msghdr*)call->msg,
                              call->flags);
            break;
        case MSG_SENDM:
            ret = sys_sendmmsg(call->fd, (struct mmsghdr*)call->msg, call->vlen,
                               call->flags);
            break;
        case MSG_RECVM:
            ret = sys_recvmmsg(call->fd, (struct mmsghdr*)call->msg, call->vlen,
                               call->flags, call->timeout);
            break;
        default:
            abort();
    }
    signalmanager_disable_signals(ctx);
    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallShutdown* call) {
    signalmanager_enable_signals(ctx);
    *call->ret = sys_shutdown(call->fd, call->how);
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallListen* call) {
    signalmanager_enable_signals(ctx);
    *call->ret = sys_listen(call->fd, call->backlog);
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallSockName* call) {
    int ret;
    signalmanager_enable_signals(ctx);
    if (call->type == SOCKNAME_GET) {
        ret = sys_getsockname(call->fd, call->usockaddr, call->usockaddr_len);
    } else {
        ret = sys_getpeername(call->fd, call->usockaddr, call->usockaddr_len);
    }
    signalmanager_disable_signals(ctx);
    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallSocketpair* call) {
    signalmanager_enable_signals(ctx);
    *call->ret = sys_socketpair(call->family, call->type, call->protocol,
                                call->usockvec);
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallSockOpt* call) {
    int ret;
    signalmanager_enable_signals(ctx);
    if (call->type == SOCKOPT_SET) {
        ret = sys_setsockopt(call->fd, call->level, call->optname, call->optval,
                             *call->optlen);
    } else {
        ret = sys_getsockopt(call->fd, call->level, call->optname, call->optval,
                             call->optlen);
    }
    signalmanager_disable_signals(ctx);
    *call->ret = ret;
}