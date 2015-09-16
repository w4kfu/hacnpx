#include <stdio.h>
#include <Windows.h>

VOID InjectCreateProcess(PCHAR pName, PCHAR pDllName, PCHAR pCmdArg)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ULONG_PTR dwAddr;
    HANDLE hThread;
    HMODULE hKernel32;
    CHAR CurrentPath[MAX_PATH ];

    if (!GetCurrentDirectory(sizeof(CurrentPath) - 1, CurrentPath)) {
        printf("[-] InjectCreateProcess - GetCurrentDirectory failed : %lu\n", GetLastError());
        return;
    }
    hKernel32 = GetModuleHandleA("kernel32.dll");
    memset(&si, 0, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    if (!CreateProcessA(pName, pCmdArg, NULL, NULL, FALSE, CREATE_SUSPENDED, GetEnvironmentStrings(), CurrentPath, &si, &pi)) {
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

BOOL CheckIniFile(PCHAR OriginalExeName, PCHAR DllName)
{
    CHAR CurrentPath[MAX_PATH];
    CHAR FilePath[MAX_PATH];
    
    if (!GetCurrentDirectory(sizeof(CurrentPath) - 1, CurrentPath)) {
        printf("[-] CheckIniFile - GetCurrentDirectory failed : %lu\n", GetLastError());
        return FALSE;
    }
    sprintf_s(FilePath, sizeof (FilePath) - 1, "%s\\injector.ini", CurrentPath);
    if (GetPrivateProfileStringA("injector", "original_executable_name", NULL, OriginalExeName, MAX_PATH, FilePath) == 0) {
        printf("[-] CheckIniFile - GetPrivateProfileString failed : %lu\n", GetLastError());
        return FALSE;
    }
    if (GetPrivateProfileStringA("injector", "dll_name", NULL, DllName, MAX_PATH, FilePath) == 0) {
        printf("[-] CheckIniFile - GetPrivateProfileString failed : %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char *argv[])
{
    CHAR OriginalExeName[MAX_PATH];
    CHAR DllName[MAX_PATH];
    PCHAR CmdLine = NULL;
    CHAR FullCmdLine[MAX_PATH];
    
    if (CheckIniFile((PCHAR)&OriginalExeName, (PCHAR)&DllName) == TRUE) {
        printf("[+] Injecting %s into %s process\n", DllName, OriginalExeName);
        CmdLine = GetCommandLine();
        if (CmdLine) {
            CmdLine = strchr(CmdLine, ' ');
            if (CmdLine) {
                CmdLine += 2;
                sprintf_s(FullCmdLine, MAX_PATH - 1, "%s %s", OriginalExeName, CmdLine);
            }
            else {
                sprintf_s(FullCmdLine, MAX_PATH - 1, "%s", OriginalExeName);
            }
        }
        printf("[+] FullCmdLine : %s\n", FullCmdLine);
        InjectCreateProcess(OriginalExeName, DllName, FullCmdLine);
    }
    else {
        if (argc < 3) {
            printf("Usage : %s <target.exe> <dll_name.dll>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        InjectCreateProcess(argv[1], argv[2], argv[1]);
    }
    return (0);
}