
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

extern char __etext;
extern __thread ssize_t ret;

int main(void) {
    // char buf[64*1024];
    char* buf = malloc(64 * 1024);
    int fd = open("/proc/self/maps", O_RDONLY);
    ret = read(fd, buf, 64 * 1024);
    ret = write(1, buf, ret);
    puts("Hello World!");
    printf("__etext: %p\n", &__etext);
    return 0;
}
