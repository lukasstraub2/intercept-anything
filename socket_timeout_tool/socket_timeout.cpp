
#include "callhandler.h"
#include "netinet/tcp.h"
#include "mysys.h"
#include "socket_timeout.h"

class SocketTimeout final : public CallHandler {
    private:
    int set_timeout(int fd) {
        int ret;
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        ret = sys_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                             sizeof(timeout));
        if (ret < 0) {
            return ret;
        }

        return sys_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                              sizeof(timeout));
    }

    int is_tcp_socket(int fd) {
        int family, type, protocol;
        int ret;
        int len = sizeof(int);

        len = sizeof(int);
        ret = sys_getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &family, &len);
        if (ret < 0) {
            return ret;
        }

        len = sizeof(int);
        ret = sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len);
        if (ret < 0) {
            return ret;
        }

        len = sizeof(int);
        ret = sys_getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &len);
        if (ret < 0) {
            return ret;
        }

        return (family == AF_INET || family == AF_INET6) &&
               type == SOCK_STREAM && protocol == 0;
    }

    public:
    SocketTimeout(CallHandler* next) : CallHandler(next) {}

    void next(Context* ctx, const CallSocket* call) override {
        _next->next(ctx, call);

        int type = call->type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
        if ((call->family == AF_INET || call->family == AF_INET6) &&
            type == SOCK_STREAM && call->protocol == 0) {
            int ret;
            ret = set_timeout(*call->ret);
            if (ret < 0) {
                sys_close(*call->ret);
                *call->ret = ret;
            }
        }
    }

    void next(Context* ctx, const CallSockOpt* call) override {
        int ret, is_tcp;

        ret = is_tcp_socket(call->fd);
        if (ret < 0) {
            *call->ret = ret;
            return;
        }
        is_tcp = ret;

        if (is_tcp && call->level == SOL_SOCKET &&
                (call->optname == SO_RCVTIMEO) ||
            call->optname == SO_SNDTIMEO) {
            *call->ret = 0;
            return;
        }

        _next->next(ctx, call);
    }

    void next(Context* ctx, const CallConnect* call) override {
        _next->next(ctx, call);

        if (!call->is_bind && *call->ret == -EINPROGRESS) {
            sys_shutdown(call->fd, SHUT_RDWR);
            *call->ret = -ETIMEDOUT;
        }
    }
};

CallHandler* socket_timeout_init(CallHandler* next) {
    return new SocketTimeout(next);
}
