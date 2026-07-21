
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
#include "mysys.h"
#include "util.h"

#include <bits/stat.h>

class FastPath : public EmulateFileTmp {
    public:
    FastPath(CallHandler* next) : EmulateFileTmp(next) {}

    protected:
    FileAction* _mangle_path(int dirfd, const char* path) override;
};

static FileAction* file(const unsigned char* content, size_t content_len) {
    FileAction* action = (FileAction*)malloc(sizeof(FileAction) + content_len);
    *action = {0, 0500, content_len};
    memcpy(action->data, content, content_len);
    return action;
}

static char* read_file(ssize_t* size_ret, const char* path) {
    ssize_t ret;
    ssize_t size = 0;
    int fd;
    char* buf;
    struct stat st;

    *size_ret = 0;

    ret = sys_open(path, O_RDONLY, 0);
    if (ret < 0) {
        return NULL;
    }
    fd = ret;

    ret = sys_fstat(fd, &st);
    if (ret < 0 || !st.st_size) {
        sys_close(fd);
        return NULL;
    }
    size = st.st_size;

    buf = (char*)malloc(size);
    if (!buf) {
        sys_close(fd);
        return NULL;
    }

    ret = read_full(fd, buf, size);
    sys_close(fd);
    if (ret != size) {
        free(buf);
        return NULL;
    }

    *size_ret = size;
    return buf;
}

static FileAction* build_ld_so_preload(const char* path) {
    int flags = intercept_filter_flags();

    if (!flags) {
        return NULL;
    }

    ssize_t orig_size;
    char* orig_buf = read_file(&orig_size, path);

    static const struct {
        int flag;
        const char* path;
    } preload_map[] = {
        {FILTER_PROCESS, "/intercept-anything/libfastpath_preload_process.so"},
        {FILTER_MEM, "/intercept-anything/libfastpath_preload_mem.so"},
        {FILTER_FILE, "/intercept-anything/libfastpath_preload_file.so"},
        {FILTER_READWRITE,
         "/intercept-anything/libfastpath_preload_readwrite.so"},
        {FILTER_SOCKET, "/intercept-anything/libfastpath_preload_socket.so"},
        {FILTER_SENDRECV,
         "/intercept-anything/libfastpath_preload_sendrecv.so"},
        {FILTER_FD, "/intercept-anything/libfastpath_preload_fd.so"},
        {FILTER_EVENT, "/intercept-anything/libfastpath_preload_event.so"},
        {FILTER_VDSO, "/intercept-anything/libfastpath_preload_vdso.so"},
    };
    const int num_maps = sizeof(preload_map) / sizeof(preload_map[0]);

    size_t append_len = 0;
    for (int i = 0; i < num_maps; i++) {
        if (flags & preload_map[i].flag || flags & FILTER_ALL) {
            append_len += strlen(preload_map[i].path) + 1;  // +1 for '\n'
        }
    }

    int need_newline =
        (orig_size > 0 && orig_buf && orig_buf[orig_size - 1] != '\n');
    if (need_newline) {
        append_len += 1;
    }

    const size_t total_size = orig_size + append_len;
    FileAction* action = (FileAction*)malloc(sizeof(FileAction) + total_size);
    if (!action) {
        free(orig_buf);
        return nullptr;
    }
    *action = {0, 0400, total_size};
    char* ptr = action->data;

    if (orig_size > 0 && orig_buf) {
        memcpy(ptr, orig_buf, orig_size);
        ptr += orig_size;
    }
    free(orig_buf);

    if (need_newline) {
        *ptr++ = '\n';
    }

    for (int i = 0; i < num_maps; i++) {
        if (flags & preload_map[i].flag || flags & FILTER_ALL) {
            size_t len = strlen(preload_map[i].path);
            memcpy(ptr, preload_map[i].path, len);
            ptr += len;
            *ptr++ = '\n';
        }
    }

    return action;
}

FileAction* FastPath::_mangle_path(int dirfd, const char* path) {
    if (!strcmp(path, RUNTIME_PREFIX "/etc/ld.so.preload") ||
        !strcmp(path, RUNTIME_PREFIX "/etc/ld-nix.so.preload")) {
        return build_ld_so_preload(path);
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

CallHandler* fastpath_init(CallHandler* next) {
    return new FastPath(next);
}