
#include "common.h"

#include "nolibc.h"
#include "loader.h"
#include "execve_here.h"

int loader_open(const char* path, int flags, mode_t mode) {
    return sys_open(path, flags, mode);
}

int main(int argc, char** argv) {
    char* args[] = {"ls", NULL};
    execve_here("/bin/ls", args, environ, NULL, NULL);
}