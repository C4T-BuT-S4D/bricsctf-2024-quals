#include <Windows.h>


typedef HANDLE(NTAPI* pCreateFileW) (
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

typedef DWORD(NTAPI* pGetFileSize) (
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
);

typedef BOOL(NTAPI* pReadFile) (
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL(NTAPI* pCryptProtectMemory) (
    LPVOID pDataIn,
    DWORD  cbDataIn,
    DWORD  dwFlags
);

typedef BOOL(NTAPI* pCloseHandle) (
    HANDLE hObject
);

typedef BOOL(NTAPI* pWriteFile) (
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

typedef FARPROC (NTAPI* pGetProcAddress) (
    HMODULE hModule,
    LPCSTR  lpProcName
);

typedef HMODULE (NTAPI* pGetModuleHandleW) (
    LPCWSTR lpModuleName
);

typedef HMODULE (NTAPI* pLoadLibraryA) (
    LPCSTR lpLibFileName

);

int main() {
    pGetProcAddress get_proc_addr = (pGetProcAddress)0xAABBCCDDEEFF9988;
    pGetModuleHandleW get_module_handle = (pGetModuleHandleW)0xAABBCCDDEEFF8899;
    

    char createfile[] = { 'C', 'r','e','a','t','e','F','i','l','e','W','\0'};
    char getfilesize[] = { 'G', 'e', 't','F','i','l','e','S','i','z','e','\0' };
    wchar_t kernel32dll[] = { 'K', 'e', 'r','n','e','l','3','2','.','d','l','l','\0' };
    char cryptbasedll[] = { 'C','R','Y','P','T','B','A','S','E','.','d','l','l', '\0' };
    wchar_t wcryptbasedll[] = { 'C','R','Y','P','T','B','A','S','E','.','d','l','l', '\0' };
    char loadlib[] = { 'L','o','a','d','L','i','b','r','a','r','y', 'A','\0' };
    char readfile[] = { 'R','e','a','d','F','i','l','e','\0' };
    char crypt_prot_mem[] = { 'C','r','y','p','t','P','r','o','t','e','c','t','M','e','m','o','r','y', '\0' };
    char close_handle[] = { 'C','l','o','s','e','H','a','n','d','l','e','\0' };
    char write_file[] = { 'W','r','i','t','e','F','i','l','e','\0' };
    char dpapidll[] = { 'd','p','a','p','i','.','d','l','l','\0' };
    wchar_t wdpapidll[] = { 'd','p','a','p','i','.','d','l','l','\0' };
    char crypt32dll[] = { 'C','r','y','p','t','3','2','.','d','l','l','\0' };
    wchar_t wadvapi32dll[] = { 'A','d','v','a','p','i','3','2','.','d','l','l','\0' };

    wchar_t flag_file_path[] = { 'C',':','\\','U','s','e','r','s','\\','c','y','b','e','r','_','b','e','b','u','s','\\','D','e','s','k','t','o','p','\\','f','l','a','g','.','t','x','t','\0' };
    pLoadLibraryA loadLibrary = (pLoadLibraryA)get_proc_addr(get_module_handle(kernel32dll), loadlib);

    pCreateFileW createFile = (pCreateFileW)get_proc_addr(get_module_handle(kernel32dll), createfile);
    pGetFileSize getFileSize = (pGetFileSize)get_proc_addr(get_module_handle(kernel32dll), getfilesize);
    pReadFile readFile = (pReadFile)get_proc_addr(get_module_handle(kernel32dll), readfile);
    pCryptProtectMemory cryptProtMem = (pCryptProtectMemory)get_proc_addr(get_module_handle(wdpapidll), crypt_prot_mem);
    pCloseHandle closeHandle = (pCloseHandle)get_proc_addr(get_module_handle(kernel32dll), close_handle);
    pWriteFile writeFile = (pWriteFile)get_proc_addr(get_module_handle(kernel32dll), write_file);

    HANDLE hFlagFile = createFile(flag_file_path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    DWORD dwWritendBytes = 0;
    DWORD bufSize = getFileSize(hFlagFile, NULL) + 0x20;
    if (bufSize % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0) {
        bufSize += CRYPTPROTECTMEMORY_BLOCK_SIZE - (bufSize % CRYPTPROTECTMEMORY_BLOCK_SIZE);
    }

    BYTE buffer[2048];
    for (int i = 0; i < 2048; ++i) {
        buffer[i] = 0;
    }

    readFile(hFlagFile, buffer, bufSize, &dwWritendBytes, NULL);
    cryptProtMem(buffer, bufSize, CRYPTPROTECTMEMORY_SAME_PROCESS);
    closeHandle(hFlagFile);

    hFlagFile = createFile(flag_file_path,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        NULL,
        NULL);

    writeFile(hFlagFile, buffer, bufSize, &dwWritendBytes, NULL);
    closeHandle(hFlagFile);

    return 0;
}
