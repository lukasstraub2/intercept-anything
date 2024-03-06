
#include <stdio.h>
#include <unistd.h>

int main (int argc, char **args) {
        for (int i = 0; i < argc; i++) {
                printf("%s\n", args[i]);
        }

        sleep(10);
}
