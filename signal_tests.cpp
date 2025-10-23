
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include "arch.h"
#include "pagesize.h"

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

#define CLONE_CLEAR_SIGHAND 0x100000000ULL

struct clone_args {
    unsigned long flags;
    unsigned long pidfd;
    unsigned long child_tid;
    unsigned long parent_tid;
    unsigned long exit_signal;
    unsigned long stack;
    unsigned long stack_size;
    unsigned long tls;
    unsigned long set_tid;
    unsigned long set_tid_size;
    unsigned long cgroup;
};

__attribute__((noinline)) static pid_t _myclone(void (*fn)(),
                                                struct clone_args* args) {
    pid_t tid = my_syscall2(__NR_clone3, args, sizeof(*args));

    if (tid) {
        return tid;
    }

    fn();
    for (;;)
        my_syscall1(__NR_exit_group, 0);
}

#define mystack_size (512 * 1024)

static pid_t myclone(void (*fn)()) {
    (void)mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char* stack = (char*)mmap(NULL, mystack_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    (void)mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#ifdef stack_grows_down
    stack += mystack_size;
#endif

    struct clone_args args = {};
    args.stack = (uintptr_t)stack;
    args.stack_size = mystack_size;
    args.flags = CLONE_VFORK | CLONE_VM | CLONE_CLEAR_SIGHAND;
    args.exit_signal = SIGCHLD;

    pid_t tid = _myclone(fn, &args);

    return tid;
}

static void clear_sighand_child() {
    int ret;
    struct sigaction act;

    for (int sig = 1; sig <= 31; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP) {
            continue;
        }
        ret = sigaction(sig, nullptr, &act);
        if (ret < 0) {
            exit_error("sigaction(%u): %s", sig, strerror(errno));
        }

        if (sigismember(&act.sa_mask, SIGWINCH)) {
            exit_error("signal was not cleared: %d", sig);
        }
    }

    for (int sig = SIGRTMIN; sig <= SIGRTMAX; sig++) {
        ret = sigaction(sig, nullptr, &act);
        if (ret < 0) {
            exit_error("sigaction(%u): %s", sig, strerror(errno));
        }

        if (sigismember(&act.sa_mask, SIGWINCH)) {
            exit_error("signal was not cleared: %d", sig);
        }
    }
}

void test_clear_sighand() {
    int ret;
    sigset_t set;
    sigemptyset(&set);

    clear_all();

    sigaddset(&set, SIGWINCH);
    struct sigaction sa = {};
    sa.sa_mask = set;
    sa.sa_handler = SIG_IGN;
    ret = sigaction(SIGWINCH, &sa, nullptr);

    ret = myclone(clear_sighand_child);
    if (ret < 0) {
        exit_error("myclone(): %s\n", strerror(-ret));
    }

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

    ret = WTERMSIG(wstatus);
    if (ret != 0) {
        exit_error("child terminated with signal %u", ret);
    }
}

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--preserve_sigprocmask_child")) {
        preserve_sigprocmask_child();
        return 0;
    }

    test_preserve_sigprocmask();
    test_clear_sighand();

    return 0;
}