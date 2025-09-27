
#include "common.h"

#include "nolibc.h"
#include "execve_thread.h"

int main(int argc, char** argv) {
    char* args[] = {"ls", NULL};
    execve_here("/bin/ls", args, environ, NULL, NULL);
}