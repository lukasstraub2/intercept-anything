
#include "common.h"
#include "nolibc.h"

#include "mysys.h"
#include "workarounds.h"
#include "intercept.h"
#include "linux/ptrace.h"

struct This {
	CallHandler this;
	const CallHandler *next;
};

static void maybe_recitfy_traceme(Tls *tls) {
	if (tls->workarounds_traceme) {
		long ret = sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (ret < 0) {
			abort();
		}
	}
}

int workarounds_rethrow_signal(Tls *tls, int signum) {
	if (signum == SIGBUS || signum == SIGFPE || signum == SIGILL || signum == SIGSEGV) {
		if (tls->workarounds_traceme) {
			long ret = sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
			if (ret < 0) {
				abort();
			}

			return 1;
		}
	}

	return 0;
}

static int workarounds_exec(Context *ctx, const This *this,
							const CallExec *call) {
	if (call->final) {
		maybe_recitfy_traceme(ctx->tls);
	}

	return this->next->exec(ctx, this->next->exec_next, call);
}

// Workaround for gdb when using vfork:
// Delay PTRACE_TRACEME until just before the exec()
static long workarounds_ptrace(Context *ctx, const This *this,
							   const CallPtrace *call) {
	const char *basename = strrchr(self_exe, '/') + 1;

	if (!strcmp(basename, "gdb") && call->request == PTRACE_TRACEME) {
		ctx->tls->workarounds_traceme = 1;
		return 0;
	}

	return this->next->ptrace(ctx, this->next->ptrace_next, call);
}

static int workarounds_kill(Context *ctx, const This *this,
							const CallKill *call) {
	maybe_recitfy_traceme(ctx->tls);

	return this->next->kill(ctx, this->next->kill_next, call);
}

const CallHandler *workarounds_init(const CallHandler *next) {
	static int initialized = 0;
	static This this;

	if (initialized) {
		return NULL;
	}
	initialized = 1;

	this.next = next;
	this.this = *next;

	this.this.exec = workarounds_exec;
	this.this.exec_next = &this;
	this.this.ptrace = workarounds_ptrace;
	this.this.ptrace_next = &this;
	this.this.kill = workarounds_kill;
	this.this.kill_next = &this;

	return &this.this;
}
