
#include "common.h"

#include "nolibc.h"
#include "mysys.h"
#include "mylock.h"
#include "linux/sched.h"
#include "tls.h"
#include "util.h"

#include "mysignal.h"
#include "asm/siginfo.h"

#define num_threads (16)
#define stack_size (512*1024)

#if defined(__x86_64__)
#define stack_grows_down
#elif defined(__aarch64__)
#define stack_grows_down
#else
#error Unsupported Architecture
#endif

static RobustMutex *mutexa = NULL;
static RobustMutex *mutexb = NULL;
static int stage[2];
static uint64_t stage_counter = 0;

static uint64_t counter = 0;
static int pipefd[2];

static pid_t tid[num_threads];
static int sem[2];

__attribute__((noinline))
static pid_t _thread_new(void (*fn)(), void *stack) {
	pid_t tid = my_syscall5(__NR_clone,
							CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM,
							stack, 0, 0, 0);

	if (tid) {
		return tid;
	}

	fn();
	sys_exit(0);
}

static pid_t thread_new(void (*fn)()) {
	sys_mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	void *stack = sys_mmap(NULL, stack_size, PROT_READ|PROT_WRITE,
						   MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0);
	sys_mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#ifdef stack_grows_down
	stack += stack_size;
#endif
	pid_t tid = _thread_new(fn, stack);

	return tid;
}

static void handler(int sig, siginfo_t *info, void *ucontext);
static void install_sighandler() {
	struct sigaction sig = {0};
	sig.sa_handler = (void *) handler;
	//sigemptyset(&sig.sa_mask);
	sig.sa_flags = SA_NODEFER | SA_SIGINFO;

	unsigned long unblock = (1u << (SIGSYS -1));
	sys_rt_sigprocmask(SIG_UNBLOCK, &unblock, NULL, sizeof(unblock));

	sigaction(SIGSYS, &sig, NULL);
}

static void rwrite(int fd, uint64_t val) {
	ssize_t ret;

	ret = sys_write(fd, &val, sizeof(val));
	if (ret != sizeof(val)) {
		abort();
	}
}

static void rsplice(int from, int to) {
	ssize_t ret;

	ret = sys_splice(from, NULL, to, NULL, sizeof(uint64_t), 0);
	if (ret != sizeof(uint64_t)) {
		abort();
	}
}

static int rpending(int fd) {
	int ret, pending;

	ret = sys_ioctl(fd, FIONREAD, &pending);
	if (ret < 0) {
		abort();
	}

	return pending;
}

static void do_recover(Tls *tls) {
	int pending = rpending(stage[0]);
	int same = counter == stage_counter;

	if (pending) {
		assert(pending == sizeof(uint64_t));

		if (!same) {
			WRITE_ONCE(counter, stage_counter);
		}
		__asm volatile ("" ::: "memory");
		rsplice(stage[0], pipefd[1]);
	} else {
		uint64_t tmp;
		if (same) {
			tmp = counter + 1;
			WRITE_ONCE(stage_counter, tmp);
		} else {
			tmp = stage_counter;
		}
		__asm volatile ("" ::: "memory");
		rwrite(stage[1], tmp);
		__asm volatile ("" ::: "memory");
		WRITE_ONCE(counter, tmp);
		__asm volatile ("" ::: "memory");
		rsplice(stage[0], pipefd[1]);
	}
}

static void do_work(Tls *tls) {
	mutex_lock(tls, mutexa);
	int ownerdead = mutex_lock(tls, mutexb);
	if (ownerdead) {
		do_recover(tls);
	} else {
		uint64_t tmp = counter + 1;

		WRITE_ONCE(stage_counter, tmp);
		__asm volatile ("" ::: "memory");
		rwrite(stage[1], tmp);
		__asm volatile ("" ::: "memory");
		WRITE_ONCE(counter, tmp);
		__asm volatile ("" ::: "memory");
		rsplice(stage[0], pipefd[1]);
	}
	mutex_unlock(tls, mutexb);
	mutex_unlock(tls, mutexa);
}

static void handler(int sig, siginfo_t *info, void *ucontext) {
	Tls *tls = tls_get();

	assert(sig == SIGSYS);

	mutex_recover(tls);
	do_work(tls);

	__builtin_longjmp(tls->jumpbuf, 1);
}

__attribute__((noinline))
static void thread_loop() {
	Tls *tls = tls_get();

	while (1) {
		do_work(tls);
	}
}

static void thread() {
	Tls *tls = tls_get();

	if (!__builtin_setjmp(tls->jumpbuf)) {
		const char tmp = 'c';
		int ret = sys_write(sem[1], &tmp, 1);
		if (ret != 1) {
			abort();
		}
	}

	thread_loop();
}

static void signal_thread() {
	int i, ret;

	pid_t pid = sys_getpid();
	while (1) {
		msleep(10);
		for (i = 0; i < num_threads; i++) {
			ret = sys_tgkill(pid, tid[i], SIGSYS);
			if (ret < 0) {
				abort();
			}
		}
	}
}

static void verifier_thread() {
	uint64_t last = 0;

	while (1) {
		uint64_t tmp;
		int ret = sys_read(pipefd[0], &tmp, sizeof(tmp));
		if (ret != sizeof(tmp)) {
			abort();
		}

		assert(tmp == last + 1);
		last = tmp;
	}
}

int main(int argc, char **argv) {
	int ret;

	install_sighandler();

	tls_init();
	mutex_init();
	mutexa = mutex_alloc();
	mutexb = mutex_alloc();

	ret = sys_pipe2(stage, O_CLOEXEC);
	if (ret < 0) {
		abort();
	}

	ret = sys_pipe2(pipefd, O_CLOEXEC);
	if (ret < 0) {
		abort();
	}

	ret = sys_pipe2(sem, O_CLOEXEC);
	if (ret < 0) {
		abort();
	}

	int i;
	for (i = 0; i < num_threads; i++) {
		tid[i] = thread_new(thread);
	}

	for (i = 0; i < num_threads; i++) {
		char tmp;
		ret = sys_read(sem[0], &tmp, 1);
		if (ret != 1) {
			abort();
		}
	}

	thread_new(signal_thread);
	thread_new(verifier_thread);

	sleep(10);
	sys_exit_group(0);
	return 0;
}
