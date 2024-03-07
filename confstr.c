
#include <stdio.h>
#include <unistd.h>

int main (int argc, char **args) {
        char buf[4096];

        confstr(_CS_PATH, buf, 4096);

        printf("_CS_PATH: %s\n", buf);

        return 0;
}
