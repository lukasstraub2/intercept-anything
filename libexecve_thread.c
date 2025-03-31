
#include "execve-thread.h"
#include <pthread.h>
#include <semaphore.h>
#include <assert.h>
#include <stdlib.h>

struct Data {
    sem_t sem;
    const char* pathname;
    char** argv;
    char** envp;
};

static void post(void* data) {
    sem_t* sem = data;
    sem_post(sem);
}

static void* start(void* _data) {
    struct Data* data = _data;
    execve_here(data->pathname, data->argv, data->envp, post, &data->sem);
    abort();
}

__attribute__((visibility("default"))) void execve_thread(const char* pathname,
                                                          char** argv,
                                                          char** envp) {
    int ret;
    pthread_t thread;
    struct Data data;
    data.pathname = pathname;
    data.argv = argv;
    data.envp = envp;

    ret = sem_init(&data.sem, 0, 0);
    assert(ret == 0);

    ret = pthread_create(&thread, NULL, start, &data);
    assert(ret == 0);

    sem_wait(&data.sem);
}