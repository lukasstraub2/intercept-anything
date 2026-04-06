
#include "workarounds.h"
#include "socket_timeout.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    CallHandler* socket_timeout = socket_timeout_init(bottom);
    return workarounds_init(socket_timeout);
}