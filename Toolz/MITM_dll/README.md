# MITM_DLL

# Example

Compile example:

    > cl /Fe:exec.exe exec.cpp
    > cl /LD /Fe:example.dll example.cpp

Normal flow:

    > C:\Temp\ddd\example>exec.exe
    0x0000000000000042

Build mitm DLL:

    > gen_mitm.py example.dll
    GetValue
    > cd example_res_dir
    > make.bat
    example.c
    example.c(66): warning C4311: 'type cast': pointer truncation from 'unsigned char *' to 'unsigned int'
    example.c(66): warning C4311: 'type cast': pointer truncation from 'void *' to 'unsigned int'
    Microsoft (R) Macro Assembler (x64) Version 14.00.23026.0
    Copyright (C) Microsoft Corporation.  All rights reserved.

    Assembling: example_trampo.asm
    Microsoft (R) Incremental Linker Version 14.00.23026.0
    Copyright (C) Microsoft Corporation.  All rights reserved.

    Creating library example.lib and object example.exp

    >del *.obj

    >del *.exp

Copy executable to folder where mitm DLL has been built:

    > copy ..\exec.exe .

Execute:

    > exec.exe
    [+] hModule = 0x000000013F070000
    [+] Original DLL : 0x000007FEF9740000
    #########################################################
    [+] FuncName : GetValue
    [+] rcx : 0x0000000041414141
    [+] rdx : 0x0000000042424242
    [+] r8  : 0x0000000043434343
    [+] r9  : 0x0000000044444444
    ------
    [+] rax : 0x0000000000000042
    #########################################################

    0x0000000000000042

## example.cpp

    /*
    -------- example.cpp --------
    > cl /LD /Fe:example.dll example.cpp
    -------------------------
    */
    #include <stdio.h>
    #include <windows.h>

    #define EXPORT_FUNC extern "C" __declspec(dllexport)

    EXPORT_FUNC DWORD64 GetValue(PVOID a, PVOID b, PVOID c, PVOID d)
    {
        return 0x42;
    }

    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
    {
        UNREFERENCED_PARAMETER(hinstDLL);
        UNREFERENCED_PARAMETER(lpReserved);

        if (fdwReason == DLL_PROCESS_ATTACH) {
            return TRUE;
        }
        return TRUE;
    }

## exec.cpp

    /*
    -------- exec.cpp --------
    > cl /Fe:exec.exe exec.cpp
    -------------------------
    */
    #include <stdio.h>
    #include <Windows.h>

    typedef PVOID (__stdcall *lpfn_GetValue)(PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4);

    int main(int argc, char *argv[])
    {
        UNREFERENCED_PARAMETER(argc);
        UNREFERENCED_PARAMETER(argv);
        HMODULE hMod = NULL;
        lpfn_GetValue GetValue;

        hMod = LoadLibraryA("example.dll");
        GetValue = (lpfn_GetValue)GetProcAddress(hMod, "GetValue");
        printf("0x%p\n", GetValue((PVOID)0x41414141, (PVOID)0x42424242, (PVOID)0x43434343, (PVOID)0x44444444));
        return 0;
    }