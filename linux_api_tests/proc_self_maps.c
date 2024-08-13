
#include "mywrappers.h"

void cat(int fd){
        char buf[4096];

        while (1) {
                ssize_t read = myread(fd, buf, 4096);
                if (!read) {
                        break;
                }

                mywrite(1, buf, read);
        }
}

int buf_equal(const char *a, ssize_t a_size, const char *b, ssize_t b_size){
        if (a_size != b_size) {
                return 0;
        }

        return !memcmp(a, b, a_size);
}

int main(int argc, char **argv){
        int ret, fd;
        void *ptr;
        char before[(64*1024)];
        ssize_t size_before;
        char after[(64*1024)];
        ssize_t size_after;

        fd = myopen("/proc/self/maps", O_NOCTTY | O_CLOEXEC | O_RDONLY, 0);
        size_before = myread(fd, before, (64*1024));

        ptr = mymmap(NULL, 4096, PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        mylseek(fd, 0, SEEK_SET);

        size_after = myread(fd, after, (64*1024));

        ret = buf_equal(before, size_before, after, size_after);
        if (ret) {
                fprintf(stderr, "/proc/self/maps stayed the same\n");
                exit(1);
        }

        return 0;
}
