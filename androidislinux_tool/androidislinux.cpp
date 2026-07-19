
#include "androidislinux.h"
#include "intercept.h"
#include "callhandler.h"
#include "asm/ioctls.h"
#include "asm/termbits.h"

#include <errno.h>
#include <stdint.h>

static int baudtospeed(tcflag_t flag) {
    switch (flag & CBAUD) {
        case B0:
            return 0;
        case B50:
            return 50;
        case B75:
            return 75;
        case B110:
            return 110;
        case B134:
            return 134;
        case B150:
            return 150;
        case B200:
            return 200;
        case B300:
            return 300;
        case B600:
            return 600;
        case B1200:
            return 1200;
        case B1800:
            return 1800;
        case B2400:
            return 2400;
        case B4800:
            return 4800;
        case B9600:
            return 9600;
        case B19200:
            return 19200;
        case B38400:
            return 38400;
        case B57600:
            return 57600;
        case B115200:
            return 115200;
        case B230400:
            return 230400;
        case B460800:
            return 460800;
        case B500000:
            return 500000;
        case B576000:
            return 576000;
        case B921600:
            return 921600;
        case B1000000:
            return 1000000;
        case B1152000:
            return 1152000;
        case B1500000:
            return 1500000;
        case B2000000:
            return 2000000;
        case B2500000:
            return 2500000;
        case B3000000:
            return 3000000;
        case B3500000:
            return 3500000;
        case B4000000:
            return 4000000;
        default:
            return 115200;
    }
}

static tcflag_t speedtobaud(int speed) {
    switch (speed) {
        case 0:
            return B0;
        case 50:
            return B50;
        case 75:
            return B75;
        case 110:
            return B110;
        case 134:
            return B134;
        case 150:
            return B150;
        case 200:
            return B200;
        case 300:
            return B300;
        case 600:
            return B600;
        case 1200:
            return B1200;
        case 1800:
            return B1800;
        case 2400:
            return B2400;
        case 4800:
            return B4800;
        case 9600:
            return B9600;
        case 19200:
            return B19200;
        case 38400:
            return B38400;
        case 57600:
            return B57600;
        case 115200:
            return B115200;
        case 230400:
            return B230400;
        case 460800:
            return B460800;
        case 500000:
            return B500000;
        case 576000:
            return B576000;
        case 921600:
            return B921600;
        case 1000000:
            return B1000000;
        case 1152000:
            return B1152000;
        case 1500000:
            return B1500000;
        case 2000000:
            return B2000000;
        case 2500000:
            return B2500000;
        case 3000000:
            return B3000000;
        case 3500000:
            return B3500000;
        case 4000000:
            return B4000000;
        default:
            return B115200;  // same default as original
    }
}

class AndroidIsLinux : public CallHandler {
    public:
    AndroidIsLinux(CallHandler* next) : CallHandler(next) {}
    int get_filter_flags() override;
    void next(Context* ctx, const CallIoctl* call) override;
    void next(Context* ctx, const CallAccept* call) override;
    void next(Context* ctx, const CallMisc* call) override;
};

int AndroidIsLinux::get_filter_flags() {
    return _next->get_filter_flags() | FILTER_SOCKET | FILTER_FD;
}

static inline tcflag_t cbaud(tcflag_t c_cflag) {
    return c_cflag & CBAUD;
}

static inline tcflag_t cibaud(tcflag_t c_cflag) {
    return cbaud(c_cflag >> IBSHIFT);
}

void convert_to_termios1(struct termios* out, const struct termios2* const in) {
    memcpy(out, in, sizeof(*out));
    if ((in->c_cflag & CBAUD) == BOTHER) {
        out->c_cflag &= ~(CBAUD | CIBAUD);
        out->c_cflag |= speedtobaud(in->c_ospeed);
        out->c_cflag |= speedtobaud(in->c_ispeed) << IBSHIFT;
    }
}

void AndroidIsLinux::next(Context* ctx, const CallIoctl* call) {
    CallIoctl _call = *call;
    struct termios copy;

    switch (call->cmd) {
        case TCGETS2:
            memset((void*)call->arg, 0, sizeof(termios2));
            _call.cmd = TCGETS;
            break;

        case TCSETS2:
            _call.cmd = TCSETS;
            convert_to_termios1(&copy, (struct termios2*)call->arg);
            _call.arg = (uintptr_t)&copy;
            break;

        case TCSETSW2:
            _call.cmd = TCSETSW;
            convert_to_termios1(&copy, (struct termios2*)call->arg);
            _call.arg = (uintptr_t)&copy;
            break;

        case TCSETSF2:
            _call.cmd = TCSETSF;
            convert_to_termios1(&copy, (struct termios2*)call->arg);
            _call.arg = (uintptr_t)&copy;
            break;
    }

    _next->next(ctx, &_call);
}

void AndroidIsLinux::next(Context* ctx, const CallAccept* call) {
    CallAccept _call = *call;

    if (!call->is4) {
        _call.is4 = 1;
        _call.flags = 0;
    }

    return _next->next(ctx, &_call);
}

void AndroidIsLinux::next(Context* ctx, const CallMisc* call) {
    *call->ret = -ENOSYS;
}

CallHandler* androidislinux_init(CallHandler* next) {
    return new AndroidIsLinux(next);
}
