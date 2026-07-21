
#include "fastpath.h"
#include "emulate_file_tmp.h"
#include "fastpath_preload.h"
#include "fastpath_preload_process.h"
#include "fastpath_preload_mem.h"
#include "fastpath_preload_file.h"
#include "fastpath_preload_readwrite.h"
#include "fastpath_preload_socket.h"
#include "fastpath_preload_sendrecv.h"
#include "fastpath_preload_vdso.h"
#include "fastpath_preload_fd.h"
#include "fastpath_preload_event.h"
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

static FileAction* file(const unsigned char* content, size_t content_len) {
    FileAction* action = (FileAction*)malloc(sizeof(FileAction) + content_len);
    *action = {0, 0500, content_len};
    memcpy(action->data, content, content_len);
    return action;
}

FileAction* FastPath::_mangle_path(int dirfd, const char* path) {
    if (!strcmp(path, "/etc/ld.so.preload") ||
        !strcmp(path, "/etc/ld-nix.so.preload")) {
        const char* content;
        if (this->vdso_fastpath) {
            content =
                "/intercept-anything/libfastpath_preload_process.so\n"
                "/intercept-anything/libfastpath_preload_mem.so\n"
                "/intercept-anything/libfastpath_preload_file.so\n"
                "/intercept-anything/libfastpath_preload_readwrite.so\n"
                "/intercept-anything/libfastpath_preload_socket.so\n"
                "/intercept-anything/libfastpath_preload_sendrecv.so\n"
                "/intercept-anything/libfastpath_preload_fd.so\n"
                "/intercept-anything/libfastpath_preload_event.so\n"
                "/intercept-anything/libfastpath_preload_vdso.so\n";
        } else {
            content =
                "/intercept-anything/libfastpath_preload_process.so\n"
                "/intercept-anything/libfastpath_preload_mem.so\n"
                "/intercept-anything/libfastpath_preload_file.so\n"
                "/intercept-anything/libfastpath_preload_readwrite.so\n"
                "/intercept-anything/libfastpath_preload_socket.so\n"
                "/intercept-anything/libfastpath_preload_sendrecv.so\n"
                "/intercept-anything/libfastpath_preload_fd.so\n"
                "/intercept-anything/libfastpath_preload_event.so\n";
        }
        size_t content_len = strlen(content);
        FileAction* action =
            (FileAction*)malloc(sizeof(FileAction) + content_len);
        *action = {0, 0400, content_len};
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
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_process.so")) {
        return file(FASTPATH_PRELOAD_PROCESS, FASTPATH_PRELOAD_PROCESS_SIZE);
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_mem.so")) {
        return file(FASTPATH_PRELOAD_MEM, FASTPATH_PRELOAD_MEM_SIZE);
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_file.so")) {
        return file(FASTPATH_PRELOAD_FILE, FASTPATH_PRELOAD_FILE_SIZE);
    } else if (!strcmp(
                   path,
                   "/intercept-anything/libfastpath_preload_readwrite.so")) {
        return file(FASTPATH_PRELOAD_READWRITE,
                    FASTPATH_PRELOAD_READWRITE_SIZE);
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_socket.so")) {
        return file(FASTPATH_PRELOAD_SOCKET, FASTPATH_PRELOAD_SOCKET_SIZE);
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_sendrecv.so")) {
        return file(FASTPATH_PRELOAD_SENDRECV, FASTPATH_PRELOAD_SENDRECV_SIZE);
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_vdso.so")) {
        return file(FASTPATH_PRELOAD_VDSO, FASTPATH_PRELOAD_VDSO_SIZE);
    } else if (!strcmp(path, "/intercept-anything/libfastpath_preload_fd.so")) {
        return file(FASTPATH_PRELOAD_FD, FASTPATH_PRELOAD_FD_SIZE);
    } else if (!strcmp(path,
                       "/intercept-anything/libfastpath_preload_event.so")) {
        return file(FASTPATH_PRELOAD_EVENT, FASTPATH_PRELOAD_EVENT_SIZE);
    }

    return nullptr;
}

CallHandler* fastpath_init(CallHandler* next, int vdso_fastpath) {
    return new FastPath(next, vdso_fastpath);
}