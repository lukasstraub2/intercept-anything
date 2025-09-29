
#include "execve_thread.h"
#include <jni.h>
#include <stdlib.h>
#include <string.h>

extern char** environ;

JNIEXPORT void JNICALL
Java_me_lukasstraub2_android_libexecve_1thread_ExecveThread_execveThread(
    JNIEnv* env,
    jclass klass,
    jbyteArray _pathname,
    jobjectArray _argv) {
    jsize argv_len = env->GetArrayLength(_argv);
    void* pathname = env->GetByteArrayElements(_pathname, nullptr);
    char** argv = alloca((argv_len + 1) * sizeof(char**));

    for (int i = 0; i < argv_len; i++) {
        jbyteArray _str = (jbyteArray)env->GetObjectArrayElement(_argv, i);
        void* str = env->GetByteArrayElements(_str, nullptr);

        argv[i] = str;
    }
    argv[argv_len] = nullptr;

    execve_thread(pathname, argv, environ);

    env->ReleaseByteArrayElements(_pathname, pathname, 0);
    for (int i = 0; i < argv_len; i++) {
        jbyteArray _str = (jbyteArray)env->GetObjectArrayElement(_argv, i);
        env->ReleaseByteArrayElements(_str, (void*)argv[i], 0);
    }
}
