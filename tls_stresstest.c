
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <syscall.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

#define NUM_THREADS (10000)

static sem_t thread_wait_sem, main_wait_sem;
static int global_cnt;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

__thread uint64_t local_cnt = 2;
void* thread_start(void* data) {
    int* tid = data;
    int ret;

    *tid = gettid();

    ret = sem_wait(&thread_wait_sem);
    if (ret < 0) {
        abort();
    }

    local_cnt++;
    pthread_mutex_lock(&lock);
    global_cnt++;
    pthread_mutex_unlock(&lock);

    ret = sem_post(&main_wait_sem);
    if (ret < 0) {
        abort();
    }

    local_cnt++;

    __asm volatile("" ::: "memory");
    assert(*tid == gettid());
    assert(local_cnt == 4);
    return NULL;
}

int __main_prepare_threaded();
void one_run() {
    int ret;
    pthread_t threads[NUM_THREADS] = {0};
    long tid_array[NUM_THREADS] = {0};
    global_cnt = 0;

    for (int i = 0; i < NUM_THREADS; i++) {
        ret = pthread_create(threads + i, NULL, thread_start, tid_array + i);
        if (ret < 0) {
            abort();
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        ret = sem_post(&thread_wait_sem);
        if (ret < 0) {
            abort();
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        ret = sem_wait(&main_wait_sem);
        if (ret < 0) {
            abort();
        }
    }

    assert(global_cnt == NUM_THREADS);

    for (int i = 0; i < NUM_THREADS; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret < 0) {
            abort();
        }
    }
}

int main(void) {
    int ret;

    ret = sem_init(&thread_wait_sem, 0, 0);
    if (ret < 0) {
        abort();
    }

    ret = sem_init(&main_wait_sem, 0, 0);
    if (ret < 0) {
        abort();
    }

    for (int i = 0; i < 10; i++) {
        one_run();
    }

    return 0;
}
