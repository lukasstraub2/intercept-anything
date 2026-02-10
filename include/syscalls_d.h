#pragma once

#include "base_types.h"
#include "myseccomp.h"
#include "syscalls.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>

class CallSocket final : public CallBase {
    public:
    int family{};
    int type{};
    int protocol{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum SendRecvType { SENDRECV_SENDTO, SENDRECV_RECVFROM };

class CallSendRecv final : public CallBase {
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

class CallMsg final : public CallBase {
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

class CallShutdown final : public CallBase {
    public:
    int fd{};
    int how{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallListen final : public CallBase {
    public:
    int fd{};
    int backlog{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum SockNameType { SOCKNAME_GET, SOCKNAME_PEER };

class CallSockName final : public CallBase {
    public:
    SockNameType type{};
    int fd{};
    void* usockaddr{};
    int* usockaddr_len{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

class CallSocketpair final : public CallBase {
    public:
    int family{};
    int type{};
    int protocol{};
    int* usockvec{};
    int* ret{};

    void set_return(int ret) const override { *this->ret = ret; }
};

enum SockOptType { SOCKOPT_SET, SOCKOPT_GET };

class CallSockOpt final : public CallBase {
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