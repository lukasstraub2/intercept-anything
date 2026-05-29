
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

int main(int argc, char** argv) {
    char buf[32];

    errno = 0;
    ssize_t ret = read(123, buf, 32);
    printf("ret = %ld\n", ret);
    assert(ret == -1 && errno == EBADF);

    return 0;
}
