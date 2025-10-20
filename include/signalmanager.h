#pragma once

#include "intercept.h"

#include <signal.h>
#include <stdlib.h>

typedef void (*myhandler_t)(int sig, siginfo_t* info, void* ucontext);

int self_is_vfork();
void vfork_exit_callback();

void signalmanager_clean_dead(Tls* tls);
void signalmanager_please_callback(Tls* tls);
void signalmanager_install_sigsys(myhandler_t handler);
void signalmanager_enable_signals(Context* ctx);
void signalmanager_disable_signals(Context* ctx);
const CallHandler* signalmanager_init(const CallHandler* next);

enum DefaultAction {
    ACTION_CONT,
    ACTION_IGNORE,
    ACTION_STOP,
    ACTION_TERM,
    ACTION_CORE,
    ACTION_STOP_KILL
};
typedef enum DefaultAction DefaultAction;

__attribute__((unused)) static DefaultAction default_action(int signum) {
    switch (signum) {
        case SIGHUP:
            // Term
            return ACTION_TERM;
            break;

        case SIGINT:
            // Term
            return ACTION_TERM;
            break;

        case SIGQUIT:
            // Core
            return ACTION_CORE;
            break;

        case SIGILL:
            // Core
            return ACTION_CORE;
            break;

        case SIGTRAP:
            // Core
            return ACTION_CORE;
            break;

        case SIGABRT:
            // Core
            return ACTION_CORE;
            break;

            /*
                            case SIGIOT:
                                    // equivalent to SIGABRT
                            break;
            */

        case SIGBUS:
            // Core
            return ACTION_CORE;
            break;

        case SIGFPE:
            // Core
            return ACTION_CORE;
            break;

        case SIGKILL:
            // Term
            return ACTION_STOP_KILL;
            break;

        case SIGUSR1:
            // Term
            return ACTION_TERM;
            break;

        case SIGSEGV:
            // Core
            return ACTION_CORE;
            break;

        case SIGUSR2:
            // Term
            return ACTION_TERM;
            break;

        case SIGPIPE:
            // Term
            return ACTION_TERM;
            break;

        case SIGALRM:
            // Term
            return ACTION_TERM;
            break;

        case SIGTERM:
            // Term
            return ACTION_TERM;
            break;

        case SIGSTKFLT:
            // Term
            return ACTION_TERM;
            break;

        case SIGCHLD:
            // Ign
            return ACTION_IGNORE;
            break;

        case SIGCONT:
            // Cont
            return ACTION_CONT;
            break;

        case SIGSTOP:
            // Stop
            return ACTION_STOP_KILL;
            break;

        case SIGTSTP:
            // Stop
            return ACTION_STOP;
            break;

        case SIGTTIN:
            // Stop
            return ACTION_STOP;
            break;

        case SIGTTOU:
            // Stop
            return ACTION_STOP;
            break;

        case SIGURG:
            // Ign
            return ACTION_IGNORE;
            break;

        case SIGXCPU:
            // Core
            return ACTION_CORE;
            break;

        case SIGXFSZ:
            // Core
            return ACTION_CORE;
            break;

        case SIGVTALRM:
            // Term
            return ACTION_TERM;
            break;

        case SIGPROF:
            // Term
            return ACTION_TERM;
            break;

        case SIGWINCH:
            // Ign
            return ACTION_IGNORE;
            break;

        case SIGIO:
            // Term
            return ACTION_TERM;
            break;
            /*
                            case SIGPOLL:
                                    // equivalent to SIGIO
                            break;
            */
        case SIGPWR:
            // Term
            return ACTION_TERM;
            break;

        case SIGSYS:
            // Core
            return ACTION_CORE;
            break;
            /*
                            case SIGUNUSED:
                                    // equivalent to SIGSYS
                            break;
            */
        default:
            if (signum >= 32 && signum <= 64) {
                // realtime signal
                // Term
                return ACTION_TERM;
            }
            abort();
            break;
    }
}
