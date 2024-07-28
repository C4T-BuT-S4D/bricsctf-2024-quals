#ifndef _DOLLY_H
#define _DOLLY_H

#include <string>

#include <jni.h>

#include "dropper.h"

class Dolly {

    public:
        Dolly();
        ~Dolly();

        void Run();

    private:
        void LoadLibrary();
        void InitializeJVM();
        void DefineDollyClass();

        ::Dropper Dropper;

        JNIEnv *Env;
        JavaVM *Jvm;

};

#endif /* _DOLLY_H */
