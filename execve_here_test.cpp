
#include "execve_thread.h"

extern char** environ;
int main(int argc, char** argv) {
    const char* args[] = {"ls", nullptr};
    execve_here("/bin/ls", args, environ, nullptr, nullptr);
}
