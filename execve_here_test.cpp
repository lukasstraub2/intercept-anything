
#include "mynolibc.h"

#include "execve_thread.h"

int main(int argc, char** argv) {
    const char* args[] = {"ls", nullptr};
    execve_here("/bin/ls", args, environ, nullptr, nullptr);
}
