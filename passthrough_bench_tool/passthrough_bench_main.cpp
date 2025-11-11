
#include "workarounds.h"
#include "signalmanager.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    signalmanager_skip_enable_signals(1);
    return workarounds_init(bottom);
}
