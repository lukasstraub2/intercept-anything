
#include "rootshim.h"
#include "emulate_file_tmp.h"

class RootShim : public EmulateFileTmp {
    public:
    RootShim(CallHandler* next) : EmulateFileTmp(next) {}

    FileAction* _mangle_path(int dirfd, const char* path) override;
};

FileAction* RootShim::_mangle_path(int dirfd, const char* path) {
    if (!strcmp(path, "/proc/uptime")) {
        const char* content = "106315.82 92968.73\n";
        size_t content_len = strlen(content);
        FileAction* action =
            (FileAction*)malloc(sizeof(FileAction) + content_len);
        *action = {0, 0400, content_len};
        memcpy(action->data, content, content_len);
        return action;
    }

    return NULL;
}

CallHandler* rootshim_init(CallHandler* next) {
    return new RootShim(next);
}
