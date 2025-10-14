
#include "sys.h"
#include "execve_thread.h"
#include "loader.h"
#include "trampo.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>

typedef const char* const* constchar;

__attribute__((visibility("default"))) void _execve_here(const char* pathname,
                                                         constchar argv,
                                                         constchar envp,
                                                         unsigned long* auxv,
                                                         void (*cb)(void*),
                                                         void* data) {
    struct LoaderInfo info;
    load_file(&info, pathname);

    size_t argv_size = 0, envp_size = 0, auxv_size = 0;
    size_t argv_strings = 0, envp_strings = 0;
    unsigned long argc = 0;

    for (constchar p = argv; *p; p++) {
        argc += 1;
        argv_size += sizeof(char**);
        argv_strings += strlen(*p) + 1;
    }
    argv_size += sizeof(char**);

    for (constchar p = envp; envp && *p; p++) {
        envp_size += sizeof(char**);
        envp_strings += strlen(*p) + 1;
    }
    envp_size += sizeof(char**);

    for (unsigned long* av = auxv; av[0] != AT_NULL; av += 2) {
        auxv_size += 2 * sizeof(unsigned long);
    }
    auxv_size += 2 * sizeof(unsigned long);

    size_t size = sizeof(argc);
    size += argv_size + envp_size;
    size += auxv_size;
    size += argv_strings + envp_strings;

    unsigned long frame = (unsigned long)alloca(size + 16);

    // round up to 16 bytes
    frame += 15;
    frame &= -16UL;

    unsigned long* argc_ptr = (unsigned long*)frame;
    char** argv_ptr = (char**)(frame + sizeof(argc));
    char** envp_ptr = (char**)(frame + sizeof(argc) + argv_size);
    unsigned long* auxv_ptr =
        (unsigned long*)(frame + sizeof(argc) + argv_size + envp_size);
    char* string_ptr =
        (char*)(frame + sizeof(argc) + argv_size + envp_size + auxv_size);

    memcpy(argc_ptr, &argc, sizeof(argc));

    for (constchar p = argv; *p; p++) {
        size_t len = strlen(*p) + 1;

        char* string = string_ptr;
        memcpy(string_ptr, *p, len);
        string_ptr += len;

        memcpy(argv_ptr, &string, sizeof(char*));
        argv_ptr++;
    }

    memset(argv_ptr, 0, sizeof(char*));
    argv_ptr++;

    assert(argv_ptr == envp_ptr);

    for (constchar p = envp; envp && *p; p++) {
        size_t len = strlen(*p) + 1;

        char* string = string_ptr;
        memcpy(string_ptr, *p, len);
        string_ptr += len;

        memcpy(envp_ptr, &string, sizeof(char*));
        envp_ptr++;
    }

    memset(envp_ptr, 0, sizeof(void*));
    envp_ptr++;

    assert((unsigned long)envp_ptr == (unsigned long)auxv_ptr);

    memcpy(auxv_ptr, auxv, auxv_size);

    patch_auxv(auxv_ptr, &info, argv[0]);

    if (cb) {
        cb(data);
    }

    z_trampo((void (*)(void))(info.elf_interp ? info.entry[Z_INTERP]
                                              : info.entry[Z_PROG]),
             (unsigned long*)frame, nullptr);

    abort();
}

__attribute__((visibility("default"))) void execve_here(const char* pathname,
                                                        const char* const* argv,
                                                        const char* const* envp,
                                                        void (*cb)(void*),
                                                        void* data) {
    char auxv_buf[4096];
    int fd = sys_open("/proc/self/auxv", O_RDONLY, 0);
    ssize_t ret = sys_read(fd, auxv_buf, 4096);
    assert(ret >= 0);
    sys_close(fd);

    _execve_here(pathname, argv, envp, (unsigned long*)auxv_buf, cb, data);
}
