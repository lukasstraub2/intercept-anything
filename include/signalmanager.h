#pragma once

#include "intercept.h"
#include "asm/siginfo.h"

typedef void (*myhandler_t)(int sig, siginfo_t *info, void *ucontext);

void signalmanager_install_sigsys(myhandler_t handler);
const CallHandler *signalmanager_init(const CallHandler *next);
