#include <jni.h>

extern int check(const char *flag);

JNIEXPORT jboolean JNICALL Java_Dolly_checkFlag(JNIEnv *env, jclass cls, jstring flag) {
    /* access actual flag bytes */
    void *ptr = ((void **)flag)[0];
    const char *bytes = (char *)(&((void **)ptr)[5]);

    int result = check(bytes);

    if (result < 0) {
        jclass exception = (*env)->FindClass(env, "java/lang/Exception");

        (*env)->ThrowNew(env, exception, "failed to check flag");

        return 0;
    }

    return result;
}
