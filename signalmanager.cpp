
#include "intercept.h"
#include "util.h"
#include "mysys.h"
#include "mysignal.h"
#include "mylock.h"
#include "myseccomp.h"
#include "signalmanager.h"
#include "rmap.h"
#include "workarounds.h"
#include "syscall_trampo.h"
#include "pagesize.h"
#include "mysys.h"
#include "util.h"
#include "mylist.h"

#define DEBUG_ENV "DEBUG_SIGNAL"
#include "debug.h"

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <pthread.h>

#define mysignal_size (64)
struct MySignal {
    pthread_mutex_t mutex;
    struct k_sigaction mysignal[mysignal_size];
};
typedef struct MySignal MySignal;

static __thread MySignal* mysignal;
static __thread int inherit_completed = 0;

struct InheritEntry {
    RLIST_ENTRY(InheritEntry) next;
    MySignal* mysignal;
    long tid;
};
typedef struct InheritEntry InheritEntry;

RLIST_HEAD(InheritHead, InheritEntry);
static InheritHead head;
static pthread_mutex_t inherit_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static void mysignal_lock() {
    int ret = pthread_mutex_lock(&mysignal->mutex);
    if (ret) {
        abort();
    }
}

static void mysignal_unlock() {
    int ret = pthread_mutex_unlock(&mysignal->mutex);
    if (ret) {
        abort();
    }
}

static MySignal* mysignal_new() {
    MySignal* signal = (MySignal*)malloc(sizeof(MySignal));
    if (!signal) {
        return nullptr;
    }

    signal->mutex = PTHREAD_MUTEX_INITIALIZER;
    return signal;
}

static void inherit_list_lock() {
    int ret = pthread_mutex_lock(&inherit_list_mutex);
    if (ret) {
        abort();
    }
}

static void inherit_list_unlock() {
    int ret = pthread_mutex_unlock(&inherit_list_mutex);
    if (ret) {
        abort();
    }
}

static InheritEntry* inherit_list_new() {
    InheritEntry* entry;
    entry = (InheritEntry*)calloc(1, sizeof(InheritEntry));
    if (!entry) {
        return nullptr;
    }

    entry->tid = -1;

    inherit_list_lock();
    RLIST_INSERT_HEAD(&head, entry, next);
    inherit_list_unlock();

    return entry;
}

static void inherit_list_maybe_inherit() {
    if (inherit_completed) {
        return;
    }
    inherit_completed = 1;

    long tid = gettid();

    inherit_list_lock();
    int found = 0;
    InheritEntry *elm, *temp;
    RLIST_FOREACH(elm, &head, next, temp) {
        long elm_tid = __atomic_load_n(&elm->tid, __ATOMIC_RELAXED);

        if (!elm_tid) {
            RLIST_REMOVE(&head, elm, next);
            free(elm);
        }

        if (elm_tid == tid) {
            found = 1;
            break;
        }
    }

    if (!found) {
        abort();
    }

    RLIST_REMOVE(&head, elm, next);
    inherit_list_unlock();

    mysignal = elm->mysignal;

    free(elm);
}

static void _sigemptyset(sigset_t* set) {
    memset(set, 0, sizeof(sigset_t));
}

static void _sigfillset(sigset_t* set) {
    memset(set, 0xff, sizeof(sigset_t));
}

static void _sigaddset(sigset_t* set, int sig) {
    unsigned s = sig - 1;
    set->__bits[s / 8 / sizeof *set->__bits] |=
        1UL << (s & 8 * sizeof *set->__bits - 1);
}

static void _sigdelset(sigset_t* set, int sig) {
    unsigned s = sig - 1;
    set->__bits[s / 8 / sizeof *set->__bits] &=
        ~(1UL << (s & 8 * sizeof *set->__bits - 1));
}

static void signotset(sigset_t* dest, const sigset_t* left) {
    unsigned long i = 0, *d = (unsigned long*)dest, *l = (unsigned long*)left;
    for (; i < (_NSIG / 8 / sizeof(long)); i++) {
        d[i] = ~l[i];
    }
}

static const sigset_t* full_mask() {
    static sigset_t set;
    static int init = 0;

    if (init) {
        return &set;
    }

    _sigfillset(&set);
    _sigdelset(&set, SIGBUS);
    _sigdelset(&set, SIGFPE);
    _sigdelset(&set, SIGILL);
    _sigdelset(&set, SIGSEGV);
    _sigdelset(&set, SIGSYS);
    _sigdelset(&set, SIGABRT);
    init = 1;

    return &set;
}

void signalmanager_please_callback(Tls* tls) {
    (void)tls;
    inherit_list_maybe_inherit();
}

static void raise_unmasked(int signum) {
    int ret;
    struct k_sigaction act = {};
    act.handler = SIG_DFL;
    struct k_sigaction oldact;
    const sigset_t empty = {};
    sigset_t oldset;

    ret = sys_rt_sigaction(signum, &act, &oldact);
    if (ret < 0) {
        exit_error("rt_sigaction(%d): %d", signum, ret);
    }

    ret = sys_rt_sigprocmask(SIG_SETMASK, &empty, &oldset);
    if (ret < 0) {
        exit_error("rt_sigprocmask(0): %d", ret);
    }

    raise(signum);

    ret = sys_rt_sigprocmask(SIG_SETMASK, &oldset, nullptr);
    if (ret < 0) {
        exit_error("rt_sigprocmask(oldset): %d", ret);
    }

    ret = sys_rt_sigaction(signum, &oldact, nullptr);
    if (ret < 0) {
        exit_error("rt_sigaction(%d): %d", signum, ret);
    }
}

static void handle_default(int signum) {
    DefaultAction def = default_action(signum);

    switch (def) {
        case ACTION_CONT:
        case ACTION_IGNORE:
            return;

        case ACTION_STOP:
        case ACTION_TERM:
        case ACTION_CORE:
        case ACTION_STOP_KILL:
            raise_unmasked(signum);
    }
}

static void generic_handler(int signum, siginfo_t* info, void* ucontext) {
    struct ucontext* uctx = (struct ucontext*)ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;
    Tls* tls = tls_get();
    mutex_recover(tls);

    if (workarounds_rethrow_signal(tls, signum)) {
        return;
    }

    if (pc_in_our_code(ucontext) && !sigismember(full_mask(), signum)) {
        raise_unmasked(signum);
    }

    inherit_list_maybe_inherit();
    mysignal_lock();
    struct k_sigaction* ptr = mysignal->mysignal + signum - 1;
    const struct k_sigaction copy = *ptr;

    if (ptr->flags & SA_RESETHAND) {
        ptr->handler = SIG_DFL;
    }
    mysignal_unlock();

    void (*const handler)(int) = copy.handler;
    const myhandler_t _handler = (myhandler_t)handler;

    if (handler == SIG_DFL) {
        trace_plus("signal %d: SIG_DFL\n", signum);
        handle_default(signum);
    } else if (handler == SIG_IGN) {
        trace_plus("signal %d: SIG_IGN\n", signum);
        // noop
    } else {
        trace_plus("signal %d: registered handler\n");
        sigset_t sa_mask = {};
        memcpy(&sa_mask, copy.mask, _NSIG / 8);
        if (!(copy.flags & SA_NODEFER)) {
            sigaddset(&sa_mask, signum);
        }
        sigset_t set = {};
        memcpy(&set, uctx_set, _NSIG / 8);
        sigorset(&set, &set, &sa_mask);
        sigandset(&set, &set, full_mask());

        int ret = sys_rt_sigprocmask(SIG_SETMASK, &set, nullptr);
        if (ret < 0) {
            exit_error("rt_sigprocmask(uctx_set): %d", ret);
        }

        if (copy.flags & SA_SIGINFO) {
            _handler(signum, info, ucontext);
        } else {
            handler(signum);
        }
    }
}

void signalmanager_disable_signals(Context* ctx) {
    if (!ctx->ucontext) {
        return;
    }

    int ret = sys_rt_sigprocmask(SIG_SETMASK, full_mask(), nullptr);
    if (ret < 0) {
        exit_error("rt_sigprocmask(0): %d", ret);
    }
}

void signalmanager_enable_signals(Context* ctx) {
    if (!ctx->ucontext) {
        return;
    }

    int ret;
    struct ucontext* uctx = (struct ucontext*)ctx->ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;

    ret = sys_rt_sigprocmask(SIG_SETMASK, uctx_set, nullptr);
    if (ret < 0) {
        exit_error("rt_sigprocmask(uctx_set): %d", ret);
    }
}

static int signalmanager_sigprocmask(Context* ctx,
                                     const This* sigmgmt,
                                     const CallSigprocmask* call) {
    int* _ret = call->ret;
    struct ucontext* uctx = (struct ucontext*)ctx->ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;
    sigset_t set = {};

    if (call->sigsetsize > _NSIG / 8) {
        *_ret = -EINVAL;
        goto out;
    }

    if (call->oldset) {
        memcpy(call->oldset, uctx_set, call->sigsetsize);
    }

    if (!call->set) {
        *_ret = 0;
        goto out;
    }

    memcpy(&set, call->set, call->sigsetsize);
    sigandset(&set, &set, full_mask());

    // Any changes to sigprocmask would be reset on sigreturn
    switch (call->how) {
        case SIG_BLOCK:
            sigorset(uctx_set, uctx_set, &set);
            *_ret = 0;
            break;

        case SIG_UNBLOCK:
            signotset(&set, &set);
            sigandset(uctx_set, uctx_set, &set);
            *_ret = 0;
            break;

        case SIG_SETMASK:
            memcpy(uctx_set, &set, _NSIG / 8);
            *_ret = 0;
            break;

        default:
            *_ret = -EINVAL;
            break;
    }

out:
    return *_ret;
}

static int install_generic_handler(int signum,
                                   const struct k_sigaction* const act);

static int signalmanager_sigaction(Context* ctx,
                                   const This* sigmgmt,
                                   const CallSigaction* call) {
    int* _ret = call->ret;
    struct k_sigaction* mysig = nullptr;

    if (call->signum <= 0 || call->sigsetsize != _NSIG / 8) {
        *_ret = -EINVAL;
        goto out;
    }

    mysignal_lock();
    mysig = mysignal->mysignal + call->signum - 1;

    if (call->oldact) {
        *call->oldact = *mysig;
    }

    if (call->act) {
        mysignal->mysignal[call->signum - 1] = *call->act;
    }

    if (call->signum == SIGSYS) {
        *_ret = 0;
        goto out;
    }

    if (call->act) {
        *_ret = install_generic_handler(call->signum, call->act);
    } else {
        *_ret = 0;
    }

out:
    mysignal_unlock();
    return *_ret;
}

static void fill_sigsys_act(struct k_sigaction* act, myhandler_t handler) {
    *act = {};
    act->handler = (decltype(act->handler))handler;
    memcpy(&act->mask, full_mask(), _NSIG / 8);
    act->flags = SA_NODEFER | SA_SIGINFO | SA_RESTORER;
    act->restorer = __restore_rt;
}

myhandler_t sigsys_handler;
void signalmanager_install_sigsys(myhandler_t handler) {
    int ret;
    struct k_sigaction act;

    sigsys_handler = handler;
    fill_sigsys_act(&act, handler);

    ret = sys_rt_sigaction(SIGSYS, &act, nullptr, _NSIG / 8);
    if (ret < 0) {
        exit_error("sigaction(): %d", -ret);
    }

    trace("registered signal handler\n");
}

static void fill_generic_handler(int signum,
                                 struct k_sigaction* dst,
                                 const struct k_sigaction* const act) {
    DefaultAction def = default_action(signum);
    *dst = *act;

    if (act->handler == SIG_DFL) {
        switch (def) {
            case ACTION_CONT:
            case ACTION_IGNORE:
                break;

            case ACTION_STOP:
            case ACTION_TERM:
            case ACTION_CORE:
                dst->handler = (decltype(dst->handler))generic_handler;
                memcpy(&dst->mask, full_mask(), _NSIG / 8);
                dst->flags &= ~(SA_RESETHAND);
                // TODO: enforce SA_NODEFER for unmasked signals
                break;

            case ACTION_STOP_KILL:
                break;
        }
    } else if (act->handler == SIG_IGN) {
        // noop
    } else {
        dst->handler = (decltype(dst->handler))generic_handler;
        memcpy(&dst->mask, full_mask(), _NSIG / 8);
        dst->flags &= ~(SA_RESETHAND);
        // TODO: enforce SA_NODEFER for unmasked signals
    }

    dst->flags |= SA_SIGINFO;

    if (!(dst->flags & SA_RESTORER)) {
        dst->flags |= SA_RESTORER;
        dst->restorer = __restore_rt;
    }
}

static int install_generic_handler(int signum,
                                   const struct k_sigaction* const act) {
    struct k_sigaction copy;
    fill_generic_handler(signum, &copy, act);

    return sys_rt_sigaction(signum, &copy, nullptr);
}

struct sigmgmt_trampo_data {
    syscall_trampo_data trampo;
    sigset_t sig_mask;
    struct k_sigaction sig_dfl_act[mysignal_size];
    struct k_sigaction sig_sys;
    struct clone_args args;
};
typedef struct sigmgmt_trampo_data sigmgmt_trampo_data;

static __thread sigmgmt_trampo_data data = {};
static unsigned int* vfork_shm = nullptr;

int self_is_vfork() {
    return data.trampo.vfork;
}

void vfork_exit_callback() {
    if (vfork_shm) {
        __atomic_store_n(vfork_shm, 1, __ATOMIC_RELAXED);
        futex_wake(vfork_shm, INT_MAX);
        sys_munmap(vfork_shm, PAGE_SIZE);
        vfork_shm = nullptr;
    }
}

static int signalmanager_clone(Context* ctx,
                               const This* sigmgmt,
                               const CallClone* call) {
    int* _ret = call->ret;

    if (call->type == CLONETYPE_FORK) {
        *_ret = fork();
        return *_ret;
    }

    if (call->type == CLONETYPE_VFORK) {
        InheritEntry* inherit = inherit_list_new();
        if (!inherit) {
            *_ret = -ENOMEM;
            return *_ret;
        }

        clone_trampo_arm(&data.trampo, ctx->ucontext);
        ctx->trampo_armed = 1;
        data.trampo.set_tid_addr = (uintptr_t)&inherit->tid;

        data.trampo.vfork = 1;

        MySignal* clone = mysignal_new();
        if (!clone) {
            abort();
        }

        mysignal_lock();
        memcpy(clone->mysignal, mysignal->mysignal, sizeof(mysignal->mysignal));
        mysignal_unlock();

        inherit->mysignal = clone;

        *_ret = 0;
        return 0;
    }

    assert(call->type == CLONETYPE_CLONE || call->type == CLONETYPE_CLONE3);
    struct clone_args* args = call->args;
    struct ucontext* uctx = (struct ucontext*)ctx->ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;

    if (args->flags & CLONE_SIGHAND && args->flags & CLONE_CLEAR_SIGHAND) {
        *_ret = -EINVAL;
        return *_ret;
    }

    if (!(args->flags & CLONE_VM)) {
        unsigned int* shm;
        if (args->flags & CLONE_VFORK) {
            shm = (unsigned int*)sys_mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                          MAP_ANON | MAP_SHARED, -1, 0);
            if ((unsigned long)shm >= -4095UL) {
                *_ret = -ENOMEM;
                return *_ret;
            }
        }

        *_ret = fork();
        if (*_ret) {
            if (*_ret < 0) {
                *_ret = -errno;
                return *_ret;
            }

            if (args->flags & CLONE_PARENT_SETTID) {
                int* tidptr = (int*)args->parent_tid;
                *tidptr = *_ret;
            }

            if (args->flags & CLONE_VFORK) {
                while (!__atomic_load_n(&shm, __ATOMIC_RELAXED)) {
                    int ret = futex_wait(shm, 0);
                    if (ret == -ETIMEDOUT && is_pid_dead(*_ret)) {
                        break;
                    }
                }

                sys_munmap(shm, PAGE_SIZE);
            }
        } else {
            int* tidptr = (int*)args->child_tid;
            int tid = 0;

            if (args->flags & CLONE_CHILD_CLEARTID) {
                tid = my_syscall1(__NR_set_tid_address, tidptr);
            }

            if (args->flags & CLONE_CHILD_SETTID) {
                *tidptr = (tid ? tid : sys_gettid());
            }

            if (args->flags & CLONE_VFORK) {
                vfork_shm = shm;
            }

            if (call->type == CLONETYPE_CLONE3 &&
                (args->flags & CLONE_CLEAR_SIGHAND)) {
                memset(mysignal->mysignal, 0, sizeof(mysignal->mysignal));
                for (int signum = 1; signum <= mysignal_size; signum++) {
                    if (signum == SIGKILL || signum == SIGSTOP) {
                        continue;
                    }

                    int ret = install_generic_handler(
                        signum, mysignal->mysignal + signum - 1);
                    if (ret < 0) {
                        exit_error("rt_sigaction(): %d", ret);
                    }
                }
            }
        }
        return *_ret;
    }

    InheritEntry* inherit = inherit_list_new();
    if (!inherit) {
        *_ret = -ENOMEM;
        return *_ret;
    }

    // trampo arm waits for the reference count to drop
    clone_trampo_arm(&data.trampo, ctx->ucontext);
    ctx->trampo_armed = 1;
    data.trampo.set_tid_addr = (uintptr_t)&inherit->tid;

    if (args->flags & CLONE_VFORK) {
        data.trampo.vfork = 1;
    }

    if (!(args->flags & CLONE_SIGHAND)) {
        MySignal* clone = mysignal_new();
        if (!clone) {
            abort();
        }

        mysignal_lock();
        memcpy(clone->mysignal, mysignal->mysignal, sizeof(mysignal->mysignal));
        mysignal_unlock();

        inherit->mysignal = clone;
    }

    if (call->type == CLONETYPE_CLONE3 && (args->flags & CLONE_CLEAR_SIGHAND)) {
        sigset_t full;
        _sigfillset(&full);

        memcpy(&data.sig_mask, uctx_set, _NSIG / 8);
        memcpy(uctx_set, &full, _NSIG / 8);
        data.trampo.sig_mask = (uintptr_t)&data.sig_mask;

        // the trampoline restores the signals in reverse order
        const struct k_sigaction dfl = {};
        for (int idx = 1; idx <= mysignal_size; idx++) {
            int signum = mysignal_size + 1 - idx;
            fill_generic_handler(signum, data.sig_dfl_act + idx - 1, &dfl);
        }
        data.trampo.sig_dfl_addr = (uintptr_t)&data.sig_dfl_act;

        fill_sigsys_act(&data.sig_sys, sigsys_handler);
        data.trampo.sig_sys_addr = (uintptr_t)&data.sig_sys;

        if (!inherit->mysignal) {
            MySignal* clone = mysignal_new();
            if (!clone) {
                abort();
            }
            inherit->mysignal = clone;
        }
        memset(inherit->mysignal->mysignal, 0, sizeof(mysignal->mysignal));
    }

    if (!inherit->mysignal) {
        inherit->mysignal = mysignal;
    }

    *_ret = 0;
    return 0;
}

const CallHandler* signalmanager_init(const CallHandler* next) {
    static int initialized = 0;
    static CallHandler sigmgmt;

    if (initialized) {
        return nullptr;
    }
    initialized = 1;

    sigmgmt = *next;
    sigmgmt.sigprocmask = signalmanager_sigprocmask;
    sigmgmt.sigprocmask_next = nullptr;
    sigmgmt.sigaction = signalmanager_sigaction;
    sigmgmt.sigaction_next = nullptr;
    sigmgmt.clone = signalmanager_clone;
    sigmgmt.clone_next = nullptr;

    pthread_atfork(inherit_list_lock, inherit_list_unlock, inherit_list_unlock);

    mysignal = mysignal_new();
    if (!mysignal) {
        exit_error("mysignal_new()");
    }

    for (int signum = 1; signum <= mysignal_size; signum++) {
        if (signum == SIGKILL || signum == SIGSTOP) {
            continue;
        }

        int ret =
            install_generic_handler(signum, mysignal->mysignal + signum - 1);
        if (ret < 0) {
            exit_error("rt_sigaction(): %d", ret);
        }
    }

    inherit_completed = 1;

    sigset_t unblock = *full_mask();
    signotset(&unblock, &unblock);
    int ret = sys_rt_sigprocmask(SIG_UNBLOCK, &unblock, nullptr);
    if (ret < 0) {
        exit_error("rt_sigprocmask(): %d", -ret);
    }

    return &sigmgmt;
}
