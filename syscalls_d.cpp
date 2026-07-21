#include "intercept.h"
#include "syscalls_d.h"
#include "sched.h"
#include "util.h"
#include "signalmanager.h"
#include "bottomhandler.h"
#include "errno.h"
#include "mysys.h"
#include "time.h"

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

unsigned long handle_clock_gettime(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallClockTimeOps call;
    call.type = CLOCKTIME_GETTIME;
    call.clockid = (clockid_t)args->arg1;
    call.spec = (struct timespec*)args->arg2;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_clock_settime(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallClockTimeOps call;
    call.type = CLOCKTIME_SETTIME;
    call.clockid = (clockid_t)args->arg1;
    call.spec = (struct timespec*)args->arg2;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_clock_getres(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallClockTimeOps call;
    call.type = CLOCKTIME_GETRES;
    call.clockid = (clockid_t)args->arg1;
    call.spec = (struct timespec*)args->arg2;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_getcpu(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallGetcpu call;
    call.cpu = (unsigned int*)args->arg1;
    call.node = (unsigned int*)args->arg2;
    call.unused = (void*)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_poll(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallPoll call;
    call.type = POLL;
    call.ufds = (struct pollfd*)args->arg1;
    call.nfds = (unsigned int)args->arg2;
    call.timeout_msecs = (int)args->arg3;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_ppoll(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallPoll call;
    call.type = PPOLL;
    call.ufds = (struct pollfd*)args->arg1;
    call.nfds = (unsigned int)args->arg2;
    call.tsp = (struct __kernel_timespec*)args->arg3;
    call.sigmask = (const sigset_t*)args->arg4;
    call.sigsetsize = (size_t)args->arg5;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_epoll_create(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallEpollCreate call;
    call.type = EPOLL_CREATE;
    call.size = (int)args->arg1;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_epoll_create1(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallEpollCreate call;
    call.type = EPOLL_CREATE1;
    call.flags = (int)args->arg1;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_epoll_wait(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallEpollWait call;
    call.type = EPOLL_WAIT;
    call.epfd = (int)args->arg1;
    call.events = (struct epoll_event*)args->arg2;
    call.maxevents = (int)args->arg3;
    call.timeout = (int)args->arg4;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_epoll_pwait(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallEpollWait call;
    call.type = EPOLL_PWAIT;
    call.epfd = (int)args->arg1;
    call.events = (struct epoll_event*)args->arg2;
    call.maxevents = (int)args->arg3;
    call.timeout = (int)args->arg4;
    call.sigmask = (const sigset_t*)args->arg5;
    call.sigsetsize = (size_t)args->arg6;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_epoll_pwait2(Context* ctx, SysArgs* args) {
    long ret = 0;
    CallEpollWait call;
    call.type = EPOLL_PWAIT2;
    call.epfd = (int)args->arg1;
    call.events = (struct epoll_event*)args->arg2;
    call.maxevents = (int)args->arg3;
    call.timeout2 = (const struct __kernel_timespec*)args->arg4;
    call.sigmask = (const sigset_t*)args->arg5;
    call.sigsetsize = (size_t)args->arg6;
    call.ret = &ret;

    intercept_entrypoint->next(ctx, &call);
    return ret;
}

unsigned long handle_epoll_ctl(Context* ctx, SysArgs* args) {
    int ret = 0;
    CallEpollCtl call;
    call.epfd = (int)args->arg1;
    call.op = (int)args->arg2;
    call.fd = (int)args->arg3;
    call.event = (struct epoll_event*)args->arg4;
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

void BottomHandler::next(Context* ctx, const CallClockTimeOps* call) {
    long ret;
    switch (call->type) {
        case CLOCKTIME_GETTIME:
            // Note: This is not sys_clock_gettime, but the vdso fastpath
            ret = clock_gettime(call->clockid, call->spec);
            break;
        case CLOCKTIME_SETTIME:
            ret = sys_clock_settime(call->clockid, call->spec);
            break;
        case CLOCKTIME_GETRES:
            ret = sys_clock_getres(call->clockid, call->spec);
            break;
        default:
            abort();
    }
    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallGetcpu* call) {
    if (!call->node && !call->unused) {
        *call->cpu = sched_getcpu();
        *call->ret = 0;
        return;
    }

    *call->ret = sys_getcpu(call->cpu, call->node, call->unused);
}

void BottomHandler::next(Context* ctx, const CallPoll* call) {
    long ret;
    signalmanager_enable_signals(ctx);
    if (call->type == POLL) {
        ret = sys_poll(call->ufds, call->nfds, call->timeout_msecs);
    } else {
        ret = sys_ppoll(call->ufds, call->nfds, call->tsp, call->sigmask,
                        call->sigsetsize);
    }
    signalmanager_disable_signals(ctx);
    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallEpollCreate* call) {
    signalmanager_enable_signals(ctx);
    if (call->type == EPOLL_CREATE) {
        *call->ret = sys_epoll_create(call->size);
    } else {
        *call->ret = sys_epoll_create1(call->flags);
    }
    signalmanager_disable_signals(ctx);
}

void BottomHandler::next(Context* ctx, const CallEpollWait* call) {
    long ret;
    signalmanager_enable_signals(ctx);
    switch (call->type) {
        case EPOLL_WAIT:
            ret = sys_epoll_wait(call->epfd, call->events, call->maxevents,
                                 call->timeout);
            break;
        case EPOLL_PWAIT:
            ret =
                sys_epoll_pwait(call->epfd, call->events, call->maxevents,
                                call->timeout, call->sigmask, call->sigsetsize);
            break;
        case EPOLL_PWAIT2:
            ret = sys_epoll_pwait2(call->epfd, call->events, call->maxevents,
                                   call->timeout2, call->sigmask,
                                   call->sigsetsize);
            break;
        default:
            abort();
    }
    signalmanager_disable_signals(ctx);
    *call->ret = ret;
}

void BottomHandler::next(Context* ctx, const CallEpollCtl* call) {
    signalmanager_enable_signals(ctx);
    *call->ret = sys_epoll_ctl(call->epfd, call->op, call->fd, call->event);
    signalmanager_disable_signals(ctx);
}
