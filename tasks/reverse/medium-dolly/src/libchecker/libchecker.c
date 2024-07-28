#define PY_SSIZE_T_CLEAN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <locale.h>
#include <dlfcn.h>

#include <Python.h>


extern unsigned char Runtime[];
extern const size_t RuntimeLength;

extern unsigned char Program[];
extern const size_t ProgramLength;

char *runtimeDirectoryPath = NULL;
char *runtimeFilePath = NULL;


wchar_t *chrtowchr(const char *chr) {
    size_t length = strlen(chr);

    char *wchr = (char *)malloc(length * 8);
    mbstowcs(wchr, chr, length + 1);

    return wchr;
}

void decryptData(unsigned char *data, size_t length) {
    unsigned char tmp = 0xFF;

    for (size_t i = 0; i < length; i += 1) {
        unsigned char value = data[i];

        value = (value ^ tmp) & 0xFF;

        value = (value ^ (i)) & 0xFF;
        value = (value + (i*i)) & 0xFF;
        value = (value ^ (i*i*i)) & 0xFF;
        value = (value + (i*i*i*i)) & 0xFF;

        data[i] = value;

        tmp = (tmp + value) & 0xFF;
    }

    return;
}

void deleteRuntimeDirectory() {
    if (runtimeDirectoryPath != NULL) {
        rmdir(runtimeDirectoryPath);

        free((void *)runtimeDirectoryPath);
        runtimeDirectoryPath = NULL;
    }

    return;
}

void deleteRuntimeFile() {
    if (runtimeDirectoryPath != NULL) {
        unlink(runtimeFilePath);

        free((void *)runtimeFilePath);
        runtimeFilePath = NULL;
    }

    return;
}

void dropRuntime() {
    runtimeDirectoryPath = (char *)malloc(64);
    runtimeDirectoryPath[0] = '\x00';

    strcpy(runtimeDirectoryPath, "/tmp/dolly-XXXXXX");
    mktemp(runtimeDirectoryPath);

    int result = mkdir(runtimeDirectoryPath, 0755);
    if (result < 0) {
        puts("[-] Error: failed to create directory");
        exit(1);
    }

    atexit(deleteRuntimeDirectory);

    runtimeFilePath = (char *)malloc(64);
    runtimeFilePath[0] = '\x00';

    strcpy(runtimeFilePath, runtimeDirectoryPath);
    strcpy(runtimeFilePath + strlen(runtimeFilePath), "/runtime.zip");

    FILE *file = fopen(runtimeFilePath, "ab+");
    if (file == NULL) {
        puts("[-] Error: failed to create file");
        exit(1);
    }

    atexit(deleteRuntimeFile);

    const size_t chunkSize = 0x100000;

    decryptData(Runtime, RuntimeLength);

    // for (size_t i = 0; i < RuntimeLength; i += chunkSize) {
    //     size_t writeSize = chunkSize;

    //     if (writeSize + i > RuntimeLength) {
    //         writeSize = RuntimeLength - i;
    //     }

    //     size_t size = fwrite(Runtime + i, sizeof(unsigned char), chunkSize, file);
    //     if (size < chunkSize) {
    //         fclose(file);

    //         puts("[-] Error: failed to write data");
    //         exit(1);
    //     }
    // }

    fwrite(Runtime, sizeof(unsigned char), RuntimeLength, file);

    fclose(file);

    return;
}

void setup() {
    dropRuntime();

    PyConfig config;
    PyConfig_InitPythonConfig(&config);

    wchar_t *paths[1] = {
        chrtowchr(runtimeFilePath)
    };
    PyWideStringList list = {
        .length = 1,
        .items = paths
    };

    config.module_search_paths = list;
    config.module_search_paths_set = 1;

    config.home = chrtowchr("x");
    config.use_environment = 0;

    PyStatus status = Py_InitializeFromConfig(&config);

    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }

    return;
}

PyCodeObject *createCode() {
    decryptData(Program, ProgramLength);

    PyObject *marshal = PyImport_ImportModule("marshal");
    PyObject *program = PyBytes_FromStringAndSize(Program, ProgramLength);
    PyObject *code = PyObject_CallMethod(marshal, "loads", "O", program);

    Py_DECREF(program);
    Py_DECREF(marshal);

    return (PyCodeObject *)code;
}

PyDictObject *createGlobals() {
    PyObject *globals = PyDict_New();

    return (PyDictObject *)globals;
}

PyFunctionObject *createExec() {
    PyObject *builtins = PyImport_ImportModule("builtins");
    PyObject *name = PyUnicode_FromString("exec");
    PyObject *exec = PyObject_GetAttr(builtins, name);

    Py_DECREF(name);
    Py_DECREF(builtins);

    return (PyFunctionObject *)exec;
}

int check(const char *flag) {
    setup();

    PyCodeObject *code = createCode();
    PyFunctionObject *exec = createExec();
    PyDictObject *globals = createGlobals();

    PyBytesObject *flagObj = (PyBytesObject *)PyBytes_FromString(flag);

    PyDict_SetItemString(globals, "flag", flagObj);
    Py_DECREF(flagObj);

    PyObject_CallFunction(exec, "OO", code, globals);
    Py_DECREF(exec);
    Py_DECREF(code);

    if (PyErr_Occurred()) {
        Py_DECREF(globals);

        PyErr_Clear();

        return -1;
    }

    PyLongObject *valid = (PyLongObject *)PyDict_GetItemString(globals, "valid");

    if (valid == NULL) {
        return -1;
    }

    long result = PyLong_AsLong(valid);

    return result == 1L;
}
