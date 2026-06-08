
#include "fastpath_preload.h"
#include "sys.h"

__attribute__((visibility("hidden"))) fastpath_entry_t entry = NULL;

__attribute__((visibility("hidden"), noreturn)) void myabort() {
    sys_kill(sys_getpid(), SIGABRT);
    for (;;)
        ;
}

__attribute__((visibility("hidden"))) void maybe_init() {
    ssize_t ret;

    if (__builtin_expect(!!entry, 1)) {
        return;
    }

    ret = sys_open(PRELOAD_ENTRY_FILE, O_RDONLY, 0);
    if (ret < 0) {
        myabort();
    }
    int fd = ret;

    ret = sys_read(fd, &entry, sizeof(entry));
    sys_close(fd);

    if (ret != sizeof(entry)) {
        myabort();
    }
}