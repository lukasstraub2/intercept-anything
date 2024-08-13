
#include "mywrappers.h"

int main(int argc, char **argv){
        struct rlimit read;
        struct rlimit write;
        int ret;

        mygetrlimit(RLIMIT_NOFILE, &read);

        write.rlim_cur = 0;
        write.rlim_max = read.rlim_max;

        mysetrlimit(RLIMIT_NOFILE, &write);

        ret = open("/", O_DIRECTORY | O_RDONLY, 0);
        if (ret >= 0) {
                fprintf(stderr, "open(): Success\n");
                exit(1);
        }

        return 0;
}
