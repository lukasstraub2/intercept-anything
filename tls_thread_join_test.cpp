#include <pthread.h>
#include <stdlib.h>

char ptr;

void* thread_start(void* retp) {
    return retp;
}

int main(void) {
    int ret;
    pthread_t thread;

    ret = pthread_create(&thread, nullptr, thread_start, &ptr);
    if (ret < 0) {
        abort();
    }

    void* retp;
    ret = pthread_join(thread, &retp);
    if (ret < 0) {
        abort();
    }

    if (retp != (void*)&ptr) {
        abort();
    }

    return 0;
}