
#include "intercept.h"
#include "util.h"
#include "mysys.h"
#include "mysignal.h"
#include "mylock.h"
#include "myseccomp.h"
#include "signalmanager.h"
#include "rmap.h"
#include "workarounds.h"

#define DEBUG_ENV "DEBUG_SIGNAL"
#include "debug.h"

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

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

static int install_generic_handler(int signum,
                                   const struct k_sigaction* const act);

#define mysignal_size (64)
typedef struct MySignal MySignal;
struct MySignal {
    int staging_signum;
    struct k_sigaction staging_signal;
    struct k_sigaction mysignal[mysignal_size];
};

static RMap* map;
static RobustMutex* mutex = nullptr;

static void _signalmanager_clean_dead(Tls* tls) {
    assert(mutex_locked(tls, mutex));

    for (int i = 0; i < (int)map->alloc; i++) {
        RMapEntry* entry = map->list + i;
        if (entry->id && is_pid_dead(entry->id)) {
            void* data = entry->data;
            if (data) {
                WRITE_ONCE(entry->data, nullptr);
                __asm volatile("" ::: "memory");
                free(data);
            }
            __asm volatile("" ::: "memory");
            WRITE_ONCE(entry->id, 0);
            __asm volatile("" ::: "memory");
        }
    }
}

void signalmanager_clean_dead(Tls* tls) {
    mutex_lock(tls, mutex);
    _signalmanager_clean_dead(tls);
    mutex_unlock(tls, mutex);
}

static void recover_mysignal(MySignal* mysignal);
static MySignal* _get_mysignal(Tls* tls) {
    assert(mutex_locked(tls, mutex));

    RMapEntry* entry;
    for (int i = 0; i < 2; i++) {
        entry = rmap_get(map, tls->pid);
        if (!entry) {
            _signalmanager_clean_dead(tls);
            continue;
        }
        break;
    }
    assert(entry);
    assert(entry->id == (uint32_t)tls->pid);

    if (entry->data) {
        recover_mysignal((MySignal*)entry->data);
        return (MySignal*)entry->data;
    }

    MySignal* alloc = (MySignal*)malloc(sizeof(*alloc));

    for (int i = 0; i < (int)map->size; i++) {
        const RMapEntry* _parent_parent = map->list + i;
        if (_parent_parent->id && _parent_parent->id < (uint32_t)tls->pid &&
            _parent_parent->data) {
            MySignal* parent_parent = (MySignal*)_parent_parent->data;
            recover_mysignal(parent_parent);
            memcpy(alloc->mysignal, parent_parent->mysignal,
                   sizeof(parent_parent->mysignal));
        }
    }

    const RMapEntry* _parent = rmap_get_noalloc(map, getppid());
    if (_parent && _parent->data) {
        MySignal* parent = (MySignal*)_parent->data;
        recover_mysignal(parent);
        memcpy(alloc->mysignal, parent->mysignal, sizeof(parent->mysignal));
    }
    __asm volatile("" ::: "memory");
    WRITE_ONCE(entry->data, alloc);
    __asm volatile("" ::: "memory");

    _signalmanager_clean_dead(tls);

    return alloc;
}

static struct k_sigaction* get_mysignal(MySignal* mysignal, int signum) {
    assert(signum > 0);
    return mysignal->mysignal + signum - 1;
}

static void recover_mysignal(MySignal* mysignal) {
    int signum = mysignal->staging_signum;

    if (signum) {
        struct k_sigaction* mysig = get_mysignal(mysignal, signum);
        *mysig = mysignal->staging_signal;
        __asm volatile("" ::: "memory");
        WRITE_ONCE(mysignal->staging_signum, 0);
        __asm volatile("" ::: "memory");
    }
}

static void update_mysignal(MySignal* mysignal,
                            int signum,
                            const struct k_sigaction* act) {
    struct k_sigaction* mysig = get_mysignal(mysignal, signum);

    mysignal->staging_signal = *act;
    __asm volatile("" ::: "memory");
    WRITE_ONCE(mysignal->staging_signum, signum);
    __asm volatile("" ::: "memory");
    *mysig = mysignal->staging_signal;
    __asm volatile("" ::: "memory");
    WRITE_ONCE(mysignal->staging_signum, 0);
    __asm volatile("" ::: "memory");
}

// Get the chance to inherit signal dispositions
void signalmanager_please_callback(Tls* tls) {
    mutex_lock(tls, mutex);
    _get_mysignal(tls);
    mutex_unlock(tls, mutex);
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

    mutex_lock(tls, mutex);
    MySignal* mysignal = _get_mysignal(tls);
    struct k_sigaction* ptr = get_mysignal(mysignal, signum);
    const struct k_sigaction copy = *ptr;

    if (ptr->flags & SA_RESETHAND) {
        ptr->handler = SIG_DFL;
    }
    mutex_unlock(tls, mutex);

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

static int signalmanager_sigaction(Context* ctx,
                                   const This* sigmgmt,
                                   const CallSigaction* call) {
    int* _ret = call->ret;
    MySignal* mysignal = nullptr;
    struct k_sigaction* mysig = nullptr;

    if (call->signum <= 0 || call->sigsetsize != _NSIG / 8) {
        *_ret = -EINVAL;
        goto out;
    }

    mutex_lock(ctx->tls, mutex);
    mysignal = _get_mysignal(ctx->tls);
    mysig = get_mysignal(mysignal, call->signum);

    if (call->oldact) {
        *call->oldact = *mysig;
    }

    if (call->act) {
        update_mysignal(mysignal, call->signum, call->act);
    }
    mutex_unlock(ctx->tls, mutex);

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
    return *_ret;
}

void signalmanager_install_sigsys(myhandler_t handler) {
    int ret;
    struct sigaction sig = {};
    sig.sa_handler = (decltype(sig.sa_handler))handler;
    sig.sa_mask = *full_mask();
    sig.sa_flags = SA_NODEFER | SA_SIGINFO;

    ret = sigaction(SIGSYS, &sig, nullptr);
    if (ret < 0) {
        exit_error("sigaction(): %d", -ret);
    }

    trace("registered signal handler\n");
}

static int install_generic_handler(int signum,
                                   const struct k_sigaction* const act) {
    DefaultAction def = default_action(signum);
    struct k_sigaction copy;
    copy = *act;

    if (act->handler == SIG_DFL) {
        switch (def) {
            case ACTION_CONT:
            case ACTION_IGNORE:
                break;

            case ACTION_STOP:
            case ACTION_TERM:
            case ACTION_CORE:
                copy.handler = (decltype(copy.handler))generic_handler;
                memcpy(&copy.mask, full_mask(), _NSIG / 8);
                copy.flags &= ~(SA_RESETHAND);
                // TODO: enforce SA_NODEFER for unmasked signals
                break;

            case ACTION_STOP_KILL:
                break;
        }
    } else if (act->handler == SIG_IGN) {
        // noop
    } else {
        copy.handler = (decltype(copy.handler))generic_handler;
        memcpy(&copy.mask, full_mask(), _NSIG / 8);
        copy.flags &= ~(SA_RESETHAND);
        // TODO: enforce SA_NODEFER for unmasked signals
    }

    copy.flags |= SA_SIGINFO;

    if (!(copy.flags & SA_RESTORER)) {
        copy.flags |= SA_RESTORER;
        copy.restorer = __restore_rt;
    }

    return sys_rt_sigaction(signum, &copy, nullptr);
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

    mutex = mutex_alloc();
    map = rmap_alloc(64);

    Tls* tls = tls_get();
    mutex_lock(tls, mutex);
    MySignal* mysignal = _get_mysignal(tls);

    const struct k_sigaction dfl = {};
    for (int signum = 1; signum <= mysignal_size; signum++) {
        update_mysignal(mysignal, signum, &dfl);
    }

    sigset_t unblock = *full_mask();
    signotset(&unblock, &unblock);
    int ret = sys_rt_sigprocmask(SIG_UNBLOCK, &unblock, nullptr);
    if (ret < 0) {
        exit_error("rt_sigprocmask(): %d", -ret);
    }

    for (int signum = 1; signum <= mysignal_size; signum++) {
        if (signum == SIGKILL || signum == SIGSTOP) {
            continue;
        }

        int ret =
            install_generic_handler(signum, get_mysignal(mysignal, signum));
        if (ret < 0) {
            exit_error("rt_sigaction(): %d", ret);
        }
    }
    mutex_unlock(tls, mutex);

    return &sigmgmt;
}
