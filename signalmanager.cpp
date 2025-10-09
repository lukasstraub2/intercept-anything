
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

typedef union mysigset_t mysigset_t;
union mysigset_t {
    sigset_t sigset;
    unsigned long cast;
};

#define SIG_BIT(signum) (1lu << ((signum)-1))
const mysigset_t full_mask = {.cast = ~(SIG_BIT(SIGBUS) | SIG_BIT(SIGFPE) |
                                        SIG_BIT(SIGILL) | SIG_BIT(SIGSEGV) |
                                        SIG_BIT(SIGSYS) | SIG_BIT(SIGABRT))};

static int install_generic_handler(int signum, const struct sigaction* act);

#define mysignal_size (64)
typedef struct MySignal MySignal;
struct MySignal {
    int staging_signum;
    struct sigaction staging_signal;
    struct sigaction mysignal[mysignal_size];
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

static struct sigaction* get_mysignal(MySignal* mysignal, int signum) {
    assert(signum > 0);
    return mysignal->mysignal + signum - 1;
}

static void recover_mysignal(MySignal* mysignal) {
    int signum = mysignal->staging_signum;

    if (signum) {
        struct sigaction* mysig = get_mysignal(mysignal, signum);
        memcpy(mysig, &mysignal->staging_signal, sizeof(struct sigaction));
        __asm volatile("" ::: "memory");
        WRITE_ONCE(mysignal->staging_signum, 0);
        __asm volatile("" ::: "memory");
    }
}

static void update_mysignal(MySignal* mysignal,
                            int signum,
                            const struct sigaction* act) {
    struct sigaction* mysig = get_mysignal(mysignal, signum);

    memcpy(&mysignal->staging_signal, act, sizeof(struct sigaction));
    __asm volatile("" ::: "memory");
    WRITE_ONCE(mysignal->staging_signum, signum);
    __asm volatile("" ::: "memory");
    memcpy(mysig, &mysignal->staging_signal, sizeof(struct sigaction));
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
    struct sigaction act = {};
    act.sa_handler = SIG_DFL;
    struct sigaction oldact;
    const mysigset_t empty = {.cast = 0};
    sigset_t oldset;

    ret = sys_rt_sigaction(signum, &act, &oldact, sizeof(sigset_t));
    if (ret < 0) {
        exit_error("rt_sigaction(%d): %d", signum, ret);
    }

    ret = sys_rt_sigprocmask(SIG_SETMASK, &empty.sigset, &oldset,
                             sizeof(sigset_t));
    if (ret < 0) {
        exit_error("rt_sigprocmask(0): %d", ret);
    }

    raise(signum);

    ret = sys_rt_sigprocmask(SIG_SETMASK, &oldset, nullptr, sizeof(sigset_t));
    if (ret < 0) {
        exit_error("rt_sigprocmask(oldset): %d", ret);
    }

    ret = sys_rt_sigaction(signum, &oldact, nullptr, sizeof(sigset_t));
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

__attribute__((noinline, section("signal_entry"))) static void
generic_handler(int signum, siginfo_t* info, void* ucontext) {
    struct ucontext* uctx = (struct ucontext*)ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;
    Tls* tls = tls_get();
    mutex_recover(tls);

    if (workarounds_rethrow_signal(tls, signum)) {
        return;
    }

    if (pc_in_our_code(ucontext) && ~full_mask.cast & SIG_BIT(signum)) {
        raise_unmasked(signum);
    }

    mutex_lock(tls, mutex);
    MySignal* mysignal = _get_mysignal(tls);
    struct sigaction* ptr = get_mysignal(mysignal, signum);
    const struct sigaction copy = *ptr;

    if (ptr->sa_flags & SA_RESETHAND) {
        ptr->sa_handler = SIG_DFL;
    }
    mutex_unlock(tls, mutex);

    const __sighandler_t handler = copy.sa_handler;
    const myhandler_t _handler = (myhandler_t)handler;

    if (handler == SIG_DFL) {
        trace_plus("signal %d: SIG_DFL\n", signum);
        handle_default(signum);
    } else if (handler == SIG_IGN) {
        trace_plus("signal %d: SIG_IGN\n", signum);
        // noop
    } else {
        trace_plus("signal %d: registered handler\n");
        mysigset_t sa_mask = {.sigset = copy.sa_mask};
        if (!(copy.sa_flags & SA_NODEFER)) {
            sa_mask.cast |= SIG_BIT(signum);
        }
        mysigset_t set = {.sigset = *uctx_set};
        set.cast |= sa_mask.cast;
        set.cast &= full_mask.cast;

        int ret = sys_rt_sigprocmask(SIG_SETMASK, &set.sigset, nullptr,
                                     sizeof(sigset_t));
        if (ret < 0) {
            exit_error("rt_sigprocmask(uctx_set): %d", ret);
        }

        if (copy.sa_flags & SA_SIGINFO) {
            _handler(signum, info, ucontext);
        } else {
            handler(signum);
        }
    }

    MyJumpbuf* sp = (MyJumpbuf*)get_sp(ucontext);
    MyJumpbuf** _jumpbuf;
    for (int i = jumpbuf_alloc - 1; i >= 0; i--) {
        _jumpbuf = tls->jumpbuf + i;
#ifdef stack_grows_down
        if (*_jumpbuf && *_jumpbuf >= sp) {
            break;
        }
#else
#error Unsupported Architecture
#endif
    }

    if (*_jumpbuf) {
        assert(!memcmp((*_jumpbuf)->magic, JUMPBUF_MAGIC, JUMPBUF_MAGIC_LEN));
    }

    if (pc_in_our_code(ucontext) && *_jumpbuf) {
        MyJumpbuf* jumpbuf = *_jumpbuf;
        __asm volatile("" ::: "memory");
        WRITE_ONCE(*_jumpbuf, nullptr);
        __asm volatile("" ::: "memory");

        int ret = sys_rt_sigprocmask(SIG_SETMASK, uctx_set, nullptr,
                                     sizeof(sigset_t));
        if (ret < 0) {
            exit_error("rt_sigprocmask(uctx_set): %d", ret);
        }
        __builtin_longjmp(jumpbuf->jumpbuf, 1);
    }
}

void signalmanager_sigsys_mask_until_sigreturn(Context* ctx) {
    if (ctx->signalmanager_masked || !ctx->ucontext) {
        return;
    }

    int ret;
    struct ucontext* uctx = (struct ucontext*)ctx->ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;

    ret = sys_rt_sigprocmask(SIG_SETMASK, &full_mask.sigset, uctx_set,
                             sizeof(sigset_t));
    if (ret < 0) {
        exit_error("rt_sigprocmask(0): %d", ret);
    }

    ctx->signalmanager_masked = 1;
}

void signalmanager_sigsys_unmask(void* ucontext) {
    if (!ucontext) {
        return;
    }

    int ret;
    struct ucontext* uctx = (struct ucontext*)ucontext;
    sigset_t* uctx_set = &uctx->uc_sigmask;

    ret = sys_rt_sigprocmask(SIG_SETMASK, uctx_set, nullptr, sizeof(sigset_t));
    if (ret < 0) {
        exit_error("rt_sigprocmask(uctx_set): %d", ret);
    }
}

static int signalmanager_sigprocmask(Context* ctx,
                                     const This* sigmgmt,
                                     const CallSigprocmask* call) {
    RetInt* _ret = call->ret;
    struct ucontext* uctx = (struct ucontext*)ctx->ucontext;
    sigset_t* _uctx_set = &uctx->uc_sigmask;
    mysigset_t uctx_set = {.sigset = *_uctx_set};
    mysigset_t set = {};

    if (call->sigsetsize != sizeof(sigset_t)) {
        _ret->ret = -EINVAL;
        goto out;
    }

    if (!call->set) {
        _ret->ret = sys_rt_sigprocmask(call->how, call->set, call->oldset,
                                       call->sigsetsize);
        goto out;
    }

    set = {.sigset = *call->set};
    set.cast &= full_mask.cast;

    signalmanager_sigsys_mask_until_sigreturn(ctx);
    if (call->oldset) {
        *call->oldset = uctx_set.sigset;
    }

    // Any changes to sigprocmask would be reset on sigreturn
    switch (call->how) {
        case SIG_BLOCK:
            uctx_set.cast |= set.cast;
            _ret->ret = 0;
            break;

        case SIG_UNBLOCK:
            uctx_set.cast &= ~set.cast;
            _ret->ret = 0;
            break;

        case SIG_SETMASK:
            uctx_set.cast = set.cast;
            _ret->ret = 0;
            break;

        default:
            _ret->ret = -EINVAL;
            break;
    }
    *_uctx_set = uctx_set.sigset;

out:
    return _ret->ret;
}

static int signalmanager_sigaction(Context* ctx,
                                   const This* sigmgmt,
                                   const CallSigaction* call) {
    RetInt* _ret = call->ret;
    MySignal* mysignal = nullptr;
    struct sigaction* mysig = nullptr;

    if (call->signum <= 0 || call->sigsetsize != sizeof(sigset_t)) {
        _ret->ret = -EINVAL;
        goto out;
    }

    mutex_lock(ctx->tls, mutex);
    signalmanager_sigsys_mask_until_sigreturn(ctx);
    mysignal = _get_mysignal(ctx->tls);
    mysig = get_mysignal(mysignal, call->signum);

    if (call->oldact) {
        memcpy(call->oldact, mysig, sizeof(struct sigaction));
    }

    if (call->act) {
        update_mysignal(mysignal, call->signum, call->act);
    }
    mutex_unlock(ctx->tls, mutex);

    if (call->signum == SIGSYS) {
        _ret->ret = 0;
        goto out;
    }

    if (call->act) {
        _ret->ret = install_generic_handler(call->signum, call->act);
    } else {
        _ret->ret = 0;
    }

out:
    return _ret->ret;
}

void signalmanager_install_sigsys(myhandler_t handler) {
    int ret;
    struct sigaction sig = {};
    sig.sa_handler = (decltype(sig.sa_handler))handler;
    sig.sa_mask = full_mask.sigset;
    sig.sa_flags = SA_NODEFER | SA_SIGINFO;

    ret = sigaction(SIGSYS, &sig, nullptr);
    if (ret < 0) {
        exit_error("sigaction(): %d", -ret);
    }

    trace("registered signal handler\n");
}

static int install_generic_handler(int signum, const struct sigaction* act) {
    DefaultAction def = default_action(signum);
    struct sigaction copy;
    memcpy(&copy, act, sizeof(struct sigaction));

    if (act->sa_handler == SIG_DFL) {
        switch (def) {
            case ACTION_CONT:
            case ACTION_IGNORE:
                break;

            case ACTION_STOP:
            case ACTION_TERM:
            case ACTION_CORE:
                copy.sa_handler = (decltype(copy.sa_handler))generic_handler;
                copy.sa_mask = full_mask.sigset;
                copy.sa_flags &= ~(SA_RESETHAND);
                // TODO: enforce SA_NODEFER for unmasked signals
                break;

            case ACTION_STOP_KILL:
                break;
        }
    } else if (act->sa_handler == SIG_IGN) {
        // noop
    } else {
        copy.sa_handler = (decltype(copy.sa_handler))generic_handler;
        copy.sa_mask = full_mask.sigset;
        copy.sa_flags &= ~(SA_RESETHAND);
        // TODO: enforce SA_NODEFER for unmasked signals
    }

    copy.sa_flags |= SA_SIGINFO;

    if (!(copy.sa_flags & SA_RESTORER)) {
        copy.sa_flags |= SA_RESTORER;
        copy.sa_restorer = __restore_rt;
    }

    return sys_rt_sigaction(signum, &copy, nullptr, sizeof(sigset_t));
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

    for (int signum = 1; signum <= mysignal_size; signum++) {
        struct sigaction act;
        long ret = sys_rt_sigaction(signum, nullptr, &act, sizeof(sigset_t));
        if (ret < 0) {
            exit_error("rt_sigaction(): %ld", -ret);
        }
        update_mysignal(mysignal, signum, &act);
    }

    mysigset_t unblock = {.cast = full_mask.cast};
    unblock.cast = ~unblock.cast;
    int ret = sys_rt_sigprocmask(SIG_UNBLOCK, &unblock.sigset, nullptr,
                                 sizeof(sigset_t));
    if (ret < 0) {
        exit_error("rt_sigprocmask(): %d", -ret);
    }

    for (int signum = 1; signum <= mysignal_size; signum++) {
        if (signum == SIGKILL || signum == SIGSTOP) {
            continue;
        }

        long ret =
            install_generic_handler(signum, get_mysignal(mysignal, signum));
        if (ret < 0) {
            exit_error("rt_sigaction(): %ld", -ret);
        }
    }
    mutex_unlock(tls, mutex);

    return &sigmgmt;
}
