
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

#define DEBUG_ENV "DEBUG"
#include "debug.h"

extern char** environ;

void clear_all() {
    sigset_t set;
    sigemptyset(&set);

    struct sigaction sa = {};
    sa.sa_mask = set;
    sa.sa_handler = SIG_DFL;

    int ret = sigprocmask(SIG_SETMASK, &set, nullptr);
    if (ret < 0) {
        exit_error("sigprocmask(): %s", strerror(errno));
    }

    for (int sig = 1; sig <= 31; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP) {
            continue;
        }
        ret = sigaction(sig, &sa, nullptr);
        if (ret < 0) {
            exit_error("sigaction(%u): %s", sig, strerror(errno));
        }
    }

    for (int sig = SIGRTMIN; sig <= SIGRTMAX; sig++) {
        ret = sigaction(sig, &sa, nullptr);
        if (ret < 0) {
            exit_error("sigaction(%u): %s", sig, strerror(errno));
        }
    }
}

void preserve_sigprocmask_child() {
    sigset_t oldset;
    int ret;

    ret = sigprocmask(0, nullptr, &oldset);
    assert(!sigismember(&oldset, SIGINT));
}

void test_preserve_sigprocmask() {
    sigset_t set, oldset;
    sigemptyset(&set);
    clear_all();

    assert(!sigismember(&set, SIGINT));

    int ret = sigprocmask(0, nullptr, &oldset);

    assert(!sigismember(&oldset, SIGINT));

    ret = fork();
    if (ret) {
        // parent
        int pid = ret;
        int wstatus;
        ret = waitpid(pid, &wstatus, 0);
        if (ret < 0) {
            exit_error("waitpid(): %s", strerror(errno));
        }

        ret = WEXITSTATUS(wstatus);
        if (ret != 0) {
            exit_error("child exited with ret %u", ret);
        }
    } else {
        // child
        ret = sigprocmask(0, nullptr, &oldset);
        assert(!sigismember(&oldset, SIGINT));
        char* const argv[] = {(char* const)"/proc/self/exe",
                              (char* const)"--preserve_sigprocmask_child",
                              nullptr};
        ret = execve("/proc/self/exe", argv, environ);
        if (ret < 0) {
            exit_error("execve(): %s", strerror(errno));
        }
    }
}

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--preserve_sigprocmask_child")) {
        preserve_sigprocmask_child();
        return 0;
    }

    test_preserve_sigprocmask();

    return 0;
}