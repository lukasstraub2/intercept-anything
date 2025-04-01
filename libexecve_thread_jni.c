
#include "execve_thread.h"
#include <jni.h>
#include <stdlib.h>
#include <string.h>

extern char** environ;

JNIEXPORT void JNICALL
Java_me_lukasstraub2_android_libexecve_1thread_ExecveThread_execveThread(
    JNIEnv* env,
    jclass class,
    jbyteArray _pathname,
    jobjectArray _argv) {
    jsize argv_len = (*env)->GetArrayLength(env, _argv);
    void* pathname = (*env)->GetByteArrayElements(env, _pathname, NULL);
    char** argv = alloca((argv_len + 1) * sizeof(char**));

    for (int i = 0; i < argv_len; i++) {
        jbyteArray _str =
            (jbyteArray)(*env)->GetObjectArrayElement(env, _argv, i);
        void* str = (*env)->GetByteArrayElements(env, _str, NULL);

        argv[i] = str;
    }
    argv[argv_len] = NULL;

    execve_thread(pathname, argv, environ);

    (*env)->ReleaseByteArrayElements(env, _pathname, pathname, 0);
    for (int i = 0; i < argv_len; i++) {
        jbyteArray _str =
            (jbyteArray)(*env)->GetObjectArrayElement(env, _argv, i);
        (*env)->ReleaseByteArrayElements(env, _str, (void*)argv[i], 0);
    }
}
