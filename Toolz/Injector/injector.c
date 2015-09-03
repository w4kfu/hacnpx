#include <stdio.h>
#include <Windows.h>

void InjectCreateProcess(PCHAR pName, PCHAR pDllName)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ULONG_PTR dwAddr;
    HANDLE hThread;
    HMODULE hKernel32;

    hKernel32 = GetModuleHandleA("kernel32.dll");
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    if (!CreateProcessA(pName, NULL, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
            printf("[-] InjectCreateProcess - CreateProcessA() failed : %lu\n", GetLastError());
            exit(EXIT_FAILURE);
    }
    dwAddr = (ULONG_PTR)VirtualAllocEx(pi.hProcess, 0, strlen(pDllName) + 1, MEM_COMMIT, PAGE_READWRITE);
    if ((LPVOID)dwAddr == NULL) {
            printf("[-] InjectCreateProcess - VirtualAllocEx failed() : %lu\n", GetLastError());
            TerminateProcess(pi.hProcess, 42);
            exit(EXIT_FAILURE);
    }
    WriteProcessMemory(pi.hProcess, (LPVOID)dwAddr, (void*)pDllName, strlen(pDllName) + 1, NULL);
    hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                            (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"LoadLibraryA"),
                            (LPVOID)dwAddr, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    ResumeThread(pi.hThread);
    CloseHandle(hThread);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage : %s <target.exe> <dll_name.dll>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    InjectCreateProcess(argv[1], argv[2]);
    return (0);
}