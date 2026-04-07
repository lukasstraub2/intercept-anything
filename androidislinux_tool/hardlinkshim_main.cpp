
#include "hardlinkshim.h"
#include "workarounds.h"
#include "util.h"

CallHandler* main_init(CallHandler* const bottom, int recursing) {
    tmpdir = PREFIX "/tmp";
    const char *hardlink_prefix = getenv("HARDLINKSHIM_PREFIX");
    if (!hardlink_prefix) {
        hardlink_prefix = PREFIX "/.hardlinkshim";
    }

    const size_t hardlink_prefix_len = strlen(hardlink_prefix);
    char parent[hardlink_prefix_len + 1];
    memcpy(parent, hardlink_prefix, hardlink_prefix_len + 1);
    char *slash = strrchr(parent, '/');
    if (*(slash + 1) == '\x00') {
        *slash = '\x00';
        slash = strrchr(parent, '/');
    }
    *slash = '\x00';

    CallHandler* const hardlinkshim = hardlinkshim_init(
        bottom, bottom, recursing, parent, hardlink_prefix);
    CallHandler* const workarounds = workarounds_init(hardlinkshim);
    return workarounds;
}