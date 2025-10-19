
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <syscall.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include "arch.h"
#include "myseccomp.h"

int __set_thread_area(void*);
int __main_prepare_threaded();
int __external_thread_register(int tid);

#define stack_size (512 * 1024)

sem_t main_wait_sem;
uintptr_t dummy = 1234;

__attribute__((noinline)) static pid_t _thread_new(void (*fn)(), void* stack) {
    pid_t tid = my_syscall5(__NR_clone,
                            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                                CLONE_THREAD | CLONE_SYSVSEM,
                            stack, 0, 0, 0);

    if (tid) {
        return tid;
    }

    fn();
    for (;;)
        my_syscall1(__NR_exit, 0);
}

static pid_t thread_new(void (*fn)()) {
    (void)mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char* stack = (char*)mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    (void)mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#ifdef stack_grows_down
    stack += stack_size;
#endif
    pid_t tid = _thread_new(fn, stack);

    return tid;
}

static void thread_start() {
    int ret;
    int tid = my_syscall1(__NR_gettid, 0);

    __set_thread_area(&dummy);
    ret = __external_thread_register(tid);
    if (ret < 0) {
        abort();
    }

    ret = sem_post(&main_wait_sem);
    if (ret < 0) {
        abort();
    }

    pthread_exit(NULL);
}

void one_run() {
    void (*fn)() = thread_start;
    __asm volatile("" : "+r"(fn)::"memory");
    pid_t tid = thread_new(fn);

    int ret = sem_wait(&main_wait_sem);
    if (ret < 0) {
        abort();
    }

    while (syscall(__NR_tkill, tid, 0) == 0)
        sched_yield();
}

int main(void) {
    int ret;

    ret = __main_prepare_threaded();
    if (ret != 0) {
        abort();
    }

    ret = sem_init(&main_wait_sem, 0, 0);
    if (ret < 0) {
        abort();
    }

    for (int i = 0; i < 1000; i++) {
        one_run();
    }

    return 0;
}
