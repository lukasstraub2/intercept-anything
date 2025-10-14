
#include "sys.h"
#include "loader.h"

int loader_open(const char* path, int flags, mode_t mode) {
    return sys_open(path, flags, mode);
}