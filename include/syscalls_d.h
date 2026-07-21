#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

class CallSocket final : public ICallBase {
    public:
    int family{};
    int type{};
    int protocol{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum SendRecvType { SENDRECV_SENDTO, SENDRECV_RECVFROM };

class CallSendRecv final : public ICallBase {
    public:
    SendRecvType type{};
    int fd{};
    void* buff{};
    size_t len{};
    unsigned int flags{};
    void* addr{};
    int* addr_len{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum MsgType { MSG_SEND, MSG_RECV, MSG_SENDM, MSG_RECVM };

class CallMsg final : public ICallBase {
    public:
    MsgType type{};
    int fd{};
    void* msg{};
    unsigned int vlen{};
    unsigned int flags{};
    struct __kernel_timespec* timeout{};
    long* ret{};

    void set_return(int ret) const override { *this->ret = (long)ret; }
};

class CallShutdown final : public ICallBase {
    public:
    int fd{};
    int how{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallListen final : public ICallBase {
    public:
    int fd{};
    int backlog{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum SockNameType { SOCKNAME_GET, SOCKNAME_PEER };

class CallSockName final : public ICallBase {
    public:
    SockNameType type{};
    int fd{};
    void* usockaddr{};
    int* usockaddr_len{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallSocketpair final : public ICallBase {
    public:
    int family{};
    int type{};
    int protocol{};
    int* usockvec{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum SockOptType { SOCKOPT_SET, SOCKOPT_GET };

class CallSockOpt final : public ICallBase {
    public:
    SockOptType type{};
    int fd{};
    int level{};
    int optname{};
    void* optval{};
    int* optlen{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum ClockTimeType { CLOCKTIME_GETTIME, CLOCKTIME_SETTIME, CLOCKTIME_GETRES };

class CallClockTimeOps final : public ICallBase {
    public:
    ClockTimeType type{};
    clockid_t clockid{};
    struct timespec* spec{};
    long* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallGetcpu final : public ICallBase {
    public:
    unsigned int* cpu{};
    unsigned int* node{};
    void* unused{};
    long* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum PollType { POLL, PPOLL };

class CallPoll final : public ICallBase {
    public:
    PollType type{};
    struct pollfd* ufds{};
    unsigned int nfds{};
    int timeout_msecs{};              // for poll
    struct __kernel_timespec* tsp{};  // for ppoll
    const sigset_t* sigmask{};        // for ppoll
    size_t sigsetsize{};              // for ppoll
    long* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum EpollCreateType { EPOLL_CREATE, EPOLL_CREATE1 };

class CallEpollCreate final : public ICallBase {
    public:
    EpollCreateType type{};
    int size{};   // for epoll_create
    int flags{};  // for epoll_create1
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum EpollWaitType { EPOLL_WAIT, EPOLL_PWAIT, EPOLL_PWAIT2 };

class CallEpollWait final : public ICallBase {
    public:
    EpollWaitType type{};
    int epfd{};
    struct epoll_event* events{};
    int maxevents{};
    int timeout{};  // for epoll_wait and epoll_pwait
    const struct __kernel_timespec* timeout2{};  // for epoll_pwait2
    const sigset_t* sigmask{};
    size_t sigsetsize{};
    long* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallEpollCtl final : public ICallBase {
    public:
    int epfd{};
    int op{};
    int fd{};
    struct epoll_event* event{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

unsigned long handle_socket(Context* ctx, SysArgs* args);
unsigned long handle_sendto(Context* ctx, SysArgs* args);
unsigned long handle_recvfrom(Context* ctx, SysArgs* args);
unsigned long handle_sendmsg(Context* ctx, SysArgs* args);
unsigned long handle_recvmsg(Context* ctx, SysArgs* args);
unsigned long handle_sendmmsg(Context* ctx, SysArgs* args);
unsigned long handle_recvmmsg(Context* ctx, SysArgs* args);
unsigned long handle_shutdown(Context* ctx, SysArgs* args);
unsigned long handle_listen(Context* ctx, SysArgs* args);
unsigned long handle_getsockname(Context* ctx, SysArgs* args);
unsigned long handle_getpeername(Context* ctx, SysArgs* args);
unsigned long handle_socketpair(Context* ctx, SysArgs* args);
unsigned long handle_setsockopt(Context* ctx, SysArgs* args);
unsigned long handle_getsockopt(Context* ctx, SysArgs* args);
unsigned long handle_clock_gettime(Context* ctx, SysArgs* args);
unsigned long handle_clock_settime(Context* ctx, SysArgs* args);
unsigned long handle_clock_getres(Context* ctx, SysArgs* args);
unsigned long handle_getcpu(Context* ctx, SysArgs* args);
unsigned long handle_poll(Context* ctx, SysArgs* args);
unsigned long handle_ppoll(Context* ctx, SysArgs* args);
unsigned long handle_epoll_create(Context* ctx, SysArgs* args);
unsigned long handle_epoll_create1(Context* ctx, SysArgs* args);
unsigned long handle_epoll_wait(Context* ctx, SysArgs* args);
unsigned long handle_epoll_pwait(Context* ctx, SysArgs* args);
unsigned long handle_epoll_pwait2(Context* ctx, SysArgs* args);
unsigned long handle_epoll_ctl(Context* ctx, SysArgs* args);