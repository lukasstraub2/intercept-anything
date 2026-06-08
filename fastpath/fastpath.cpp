
#include "fastpath.h"
#include "emulate_file_tmp.h"
#include "fastpath_preload.h"
#include "fastpath_preload_data.h"
#include "fastpath_preload_vdso_data.h"
#include "intercept.h"

class FastPath : public EmulateFileTmp {
    private:
    int vdso_fastpath;

    public:
    FastPath(CallHandler* next, int vdso_fastpath)
        : EmulateFileTmp(next), vdso_fastpath(vdso_fastpath) {}

    protected:
    FileAction* _mangle_path(int dirfd, const char* path) override;
};

FileAction* FastPath::_mangle_path(int dirfd, const char* path) {
    if (!strcmp(path, "/etc/ld.so.preload") ||
        !strcmp(path, "/etc/ld-nix.so.preload")) {
        const char* content;
        if (this->vdso_fastpath) {
            content =
                "/intercept-anything/preload.so\n"
                "/intercept-anything/preload_vdso.so\n";
        } else {
            content = "/intercept-anything/preload.so\n";
        }
        size_t content_len = strlen(content);
        FileAction* action =
            (FileAction*)malloc(sizeof(FileAction) + content_len);
        *action = {0, 0400, content_len};
        memcpy(action->data, content, content_len);
        return action;
    } else if (!strcmp(path, "/intercept-anything/preload.so")) {
        const unsigned char* content = FASTPATH_PRELOAD_DATA;
        size_t content_len = FASTPATH_PRELOAD_DATA_SIZE;
        FileAction* action =
            (FileAction*)malloc(sizeof(FileAction) + content_len);
        *action = {0, 0500, content_len};
        memcpy(action->data, content, content_len);
        return action;
    } else if (!strcmp(path, "/intercept-anything/preload_vdso.so")) {
        const unsigned char* content = FASTPATH_PRELOAD_VDSO_DATA;
        size_t content_len = FASTPATH_PRELOAD_VDSO_DATA_SIZE;
        FileAction* action =
            (FileAction*)malloc(sizeof(FileAction) + content_len);
        *action = {0, 0500, content_len};
        memcpy(action->data, content, content_len);
        return action;
    } else if (!strcmp(path, PRELOAD_ENTRY_FILE)) {
        fastpath_entry_t content = fastpath_entry;
        size_t content_len = sizeof(content);
        FileAction* action =
            (FileAction*)malloc(sizeof(FileAction) + content_len);
        *action = {0, 0400, content_len};
        memcpy(action->data, &content, content_len);
        return action;
    }

    return nullptr;
}

CallHandler* fastpath_init(CallHandler* next, int vdso_fastpath) {
    return new FastPath(next, vdso_fastpath);
}