#include <stdexcept>
#include <dlfcn.h>

#include "common.h"
#include "dolly.h"

extern unsigned char DollyClass[];
extern const size_t DollyClassLength;

typedef jint (*CreateJavaVMPtr)(JavaVM **pvm, void **penv, void *args);
CreateJavaVMPtr CreateJavaVM = nullptr;

Dolly::Dolly() {
    Dropper.Drop();

    return;
}

Dolly::~Dolly() {
    if (Jvm != nullptr) {
        Jvm->DestroyJavaVM();
        Jvm = nullptr;
    }

    return;
}

void Dolly::Run() {
    Dropper.Wait();

    LoadLibrary();
    InitializeJVM();
    DefineDollyClass();

    auto dolly = Env->FindClass("Dolly");
    auto runMethod = Env->GetStaticMethodID(dolly, "run", "()V");

    Env->CallStaticVoidMethod(dolly, runMethod);
    Env->DeleteLocalRef(dolly);

    if (Env->ExceptionCheck()) {
        Env->ExceptionClear();

        throw std::runtime_error("failed to check flag");
    }

    return;
}

void Dolly::LoadLibrary() {
    auto libjvmPath = Dolly::Dropper.GetRuntimePath() / "lib" / "server" / "libjvm.so";
    auto libjvm = dlopen(libjvmPath.c_str(), RTLD_LAZY);

    if (libjvm == nullptr) {
        throw std::runtime_error("failed to load library");
    }

    auto createJavaVmPtr = dlsym(libjvm, "JNI_CreateJavaVM");

    if (createJavaVmPtr == nullptr) {
        throw std::runtime_error("failed to find method");
    }

    CreateJavaVM = reinterpret_cast<CreateJavaVMPtr>(createJavaVmPtr);

    return;
}

void Dolly::InitializeJVM() {
    JavaVMOption options[] = { 
        { .optionString = const_cast<char *>("-Xms8G") },
        { .optionString = const_cast<char *>("-Xmx8G") }
    };

    JavaVMInitArgs vmArgs = {
        .version = JNI_VERSION_1_8,
        .nOptions = 2,
        .options = options,
        .ignoreUnrecognized = JNI_FALSE,
    };

    auto status = CreateJavaVM(&Jvm, (void**)&Env, &vmArgs);

    if (status == JNI_ERR) {
        throw std::runtime_error("failed to initialize JVM");
    }

    return;
}

void Dolly::DefineDollyClass() {
    DecryptData(DollyClass, DollyClassLength);

    auto loader = Env->FindClass("java/lang/ClassLoader");
    auto getSystemClassLoader = Env->GetStaticMethodID(
        loader,
        "getSystemClassLoader",
        "()Ljava/lang/ClassLoader;"
    );
    auto systemLoader = Env->CallStaticObjectMethod(loader, getSystemClassLoader);
    auto cls = Env->DefineClass(
        "Dolly",
        systemLoader,
        reinterpret_cast<const jbyte *>(DollyClass),
        static_cast<jsize>(DollyClassLength)
    );

    if (cls == nullptr) {
        throw std::runtime_error("failed to load class");
    }

    Env->DeleteLocalRef(cls);
    Env->DeleteLocalRef(systemLoader);
    Env->DeleteLocalRef(loader);

    return;
}
