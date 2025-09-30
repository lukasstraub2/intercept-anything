
#include <stddef.h>
#include <unistd.h>
#include "execve_thread.h"

extern char** environ;

__attribute__((visibility("default"))) int main(int argc, char** argv) {
    const char* args[] = {"ls", nullptr};
    execve_thread("/bin/ls", args, environ);
    sleep(1);
}
