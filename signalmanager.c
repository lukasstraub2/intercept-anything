
#include "common.h"
#include "nolibc.h"

#include "intercept.h"
#include "util.h"
#include "mysys.h"
#include "mysignal.h"
#include "asm/siginfo.h"
#include "mylock.h"
#include "myseccomp.h"
#include "signalmanager.h"

#define DEBUG_ENV "DEBUG_SIGNAL"
#include "debug.h"

_Static_assert(sizeof(sigset_t) == 8, "sigset_t");

#define SIG_BIT(signum) (1lu << ((signum) -1))
const sigset_t unmask = SIG_BIT(SIGBUS)|SIG_BIT(SIGFPE)|SIG_BIT(SIGILL)|
		SIG_BIT(SIGSEGV)|SIG_BIT(SIGSYS);

static int install_generic_handler(int signum, const struct sigaction *act);

#define mysignal_size (64)
static struct sigaction mysignal[mysignal_size];
static struct sigaction staging_signal;
static int staging_signum = -1;
static pid_t mysignal_pid;
static RobustMutex *mutex = NULL;

static struct sigaction *get_mysignal(int signum) {
	assert(signum > 0);
	return mysignal + signum - 1;
}

static void recover_mysignal() {
	int signum = staging_signum;
	struct sigaction *mysig = get_mysignal(signum);

	if (signum > 0) {
		memcpy(mysig, &staging_signal, sizeof(struct sigaction));
		__asm volatile ("" ::: "memory");
		WRITE_ONCE(staging_signum, -1);
		__asm volatile ("" ::: "memory");
	}
}

static void update_mysignal(int signum, const struct sigaction *act) {
	struct sigaction *mysig = get_mysignal(signum);

	memcpy(&staging_signal, act, sizeof(struct sigaction));
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(staging_signum, signum);
	__asm volatile ("" ::: "memory");
	memcpy(mysig, &staging_signal, sizeof(struct sigaction));
	__asm volatile ("" ::: "memory");
	WRITE_ONCE(staging_signum, -1);
	__asm volatile ("" ::: "memory");
}

static void raise_unmasked(int signum) {
	int ret;
	struct sigaction act = {0};
	act.sa_handler = SIG_DFL;
	struct sigaction oldact;
	const sigset_t empty = 0;
	sigset_t oldset;

	ret = sys_rt_sigaction(signum, &act, &oldact, sizeof(sigset_t));
	if (ret < 0) {
		exit_error("rt_sigaction(%d): %d", signum, ret);
	}

	ret = sys_rt_sigprocmask(SIG_SETMASK, &empty, &oldset, sizeof(sigset_t));
	if (ret < 0) {
		exit_error("rt_sigprocmask(0): %d", ret);
	}

	raise(signum);

	ret = sys_rt_sigprocmask(SIG_SETMASK, &oldset, NULL, sizeof(sigset_t));
	if (ret < 0) {
		exit_error("rt_sigprocmask(oldset): %d", ret);
	}

	ret = sys_rt_sigaction(signum, &oldact, NULL, sizeof(sigset_t));
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

static void generic_handler(int signum, siginfo_t *info, void *ucontext) {
	struct sigaction *ptr = get_mysignal(signum);
	struct sigaction act;
	Tls *tls = tls_get();

	mutex_recover(tls);

	int ownerdead = mutex_lock(tls, mutex);
	if (ownerdead) {
		recover_mysignal();
	}
	memcpy(&act, ptr, sizeof(struct sigaction));
	if (ptr->sa_flags & SA_RESETHAND) {
		ptr->sa_handler = SIG_DFL;
	}
	mutex_unlock(tls, mutex);

	const __sighandler_t handler = act.sa_handler;
	const myhandler_t _handler = (void *) handler;

	if (handler == SIG_DFL) {
		trace_plus("signal %d: SIG_DFL\n", signum);
		handle_default(signum);
	} else if (handler == SIG_IGN) {
		trace_plus("signal %d: SIG_IGN\n", signum);
		// noop
	} else {
		trace_plus("signal %d: registered handler\n", signum);
		if (act.sa_flags & SA_SIGINFO) {
			_handler(signum, info, ucontext);
		} else {
			handler(signum);
		}
	}

	if (tls->jumpbuf_valid) {
		__builtin_longjmp(tls->jumpbuf, 1);
	}
}

static int signalmanager_sigprocmask(Context *ctx, const This *this, const CallSigprocmask *call) {
	RetInt *_ret = call->ret;

	if (call->sigsetsize != sizeof(sigset_t)) {
		_ret->ret = -EINVAL;
		goto out;
	}

	struct ucontext* uctx = (struct ucontext*)ctx->ucontext;
	sigset_t *uctx_set = &uctx->uc_sigmask;

	if (!call->set) {
		 _ret->ret = sys_rt_sigprocmask(call->how, call->set, call->oldset, call->sigsetsize);
		 goto out;
	}

	sigset_t set = *call->set;
	set &= ~unmask;

	_ret->ret = sys_rt_sigprocmask(call->how, &set, call->oldset, call->sigsetsize);
	if (_ret->ret < 0) {
		goto out;
	}

	// Any changes to sigprocmask would be reset on sigreturn
	switch (call->how) {
		case SIG_BLOCK:
			*uctx_set |= set;
			_ret->ret = 0;
		break;

		case SIG_UNBLOCK:
			*uctx_set &= ~set;
			_ret->ret = 0;
		break;

		case SIG_SETMASK:
			*uctx_set = set;
			_ret->ret = 0;
		break;

		default:
			_ret->ret = -EINVAL;
		break;
	}

out:
	return _ret->ret;
}

static int signalmanager_sigaction(Context *ctx, const This *this, const CallSigaction *call) {
	RetInt *_ret = call->ret;

	if (call->signum <= 0 || call->sigsetsize != sizeof(sigset_t)) {
		_ret->ret = -EINVAL;
		goto out;
	}

	struct sigaction *mysig = get_mysignal(call->signum);

	int ownerdead = mutex_lock(ctx->tls, mutex);
	if (ownerdead) {
		recover_mysignal();
	}

	if (call->oldact) {
		memcpy(call->oldact, mysig, sizeof(struct sigaction));
	}

	if (call->act) {
		update_mysignal(call->signum, call->act);
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
	struct sigaction sig = {0};
	sig.sa_handler = (void *) handler;
	sig.sa_flags = SA_NODEFER | SA_SIGINFO;

	ret = sigaction(SIGSYS, &sig, NULL);
	if (ret < 0) {
		exit_error("sigaction(): %d", -ret);
	}

	trace("registered signal handler\n");
}

static int install_generic_handler(int signum, const struct sigaction *act) {
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
				copy.sa_handler = (void *) generic_handler;
				copy.sa_mask &= ~unmask;
				copy.sa_flags &= ~(SA_RESETHAND);
				// TODO: enforce SA_NODEFER for unmasked signals
			break;

			case ACTION_STOP_KILL:
			break;
		}
	} else if (act->sa_handler == SIG_IGN) {
		// noop
	} else {
		copy.sa_handler = (void *) generic_handler;
		copy.sa_mask &= ~unmask;
		copy.sa_flags &= ~(SA_RESETHAND);
		// TODO: enforce SA_NODEFER for unmasked signals
	}

	copy.sa_flags |= SA_RESTORER;
	copy.sa_restorer = __restore_rt;

	return sys_rt_sigaction(signum, &copy, NULL, sizeof(sigset_t));
}

const CallHandler *signalmanager_init(const CallHandler *next) {
	static int initialized = 0;
	static CallHandler this;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this = *next;
	this.sigprocmask = signalmanager_sigprocmask;
	this.sigprocmask_next = NULL;
	this.sigaction = signalmanager_sigaction;
	this.sigaction_next = NULL;

	mysignal_pid = sys_getpid();
	mutex = mutex_alloc();

	for (int signum = 1; signum <= mysignal_size; signum++) {
		struct sigaction act;
		long ret = sys_rt_sigaction(signum, NULL, &act, sizeof(sigset_t));
		if (ret < 0) {
			exit_error("rt_sigaction(): %ld", -ret);
		}
		update_mysignal(signum, &act);
	}

	int ret = sys_rt_sigprocmask(SIG_UNBLOCK, &unmask, NULL, sizeof(unmask));
	if (ret < 0) {
		exit_error("rt_sigprocmask(): %d", -ret);
	}

	for (int signum = 1; signum <= mysignal_size; signum++) {
		if (signum == SIGKILL || signum == SIGSTOP) {
			continue;
		}

		long ret = install_generic_handler(signum, get_mysignal(signum));
		if (ret < 0) {
			exit_error("rt_sigaction(): %ld", -ret);
		}
	}

	return &this;
}
