#include "dbg.h"

extern PE_INFO pinfo;
CHAR REAL_DBG_PATH[512] = {0};
CHAR REAL_DBG_PATH_BIN[512] = {0};
CHAR cpBuffer[512];
CHAR bCurDir[512] = {0};

CRITICAL_SECTION CriticalSection;
BOOL bCriticalSectionInit = FALSE;

VOID InitCriticalSection(VOID)
{
    //printf("[+] InitCriticalSection!\n");
    if (bCriticalSectionInit == FALSE) {
        InitializeCriticalSection(&CriticalSection);
        bCriticalSectionInit = TRUE;
    }
}

VOID MakeConsole(VOID)
{
    DWORD dwMode;
    struct _CONSOLE_SCREEN_BUFFER_INFO sbi;
    HANDLE hStd;
    FILE *fStream;

    //if (!InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x00000400)) {
    //    DbgMsg("[-] InitializeCriticalSectionAndSpinCount failed : %lu\n", GetLastError());
    //}
    //InitializeCriticalSection(&CriticalSection);
    InitCriticalSection();
    if (!AllocConsole()) {
        FreeConsole();
        if (!AllocConsole()) {
            DbgMsg("[+] AllocConsole() failed : %lu\n", GetLastError());
        }
    }
    hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(hStd, (LPDWORD)&dwMode);
    SetConsoleMode(hStd, dwMode & 0xFFFFFFEF);
    GetConsoleScreenBufferInfo(hStd, &sbi);
    sbi.dwSize.Y = 500;
    SetConsoleScreenBufferSize(hStd, sbi.dwSize);
    freopen_s(&fStream, "conin$", "r", stdin);
    freopen_s(&fStream, "conout$", "w", stdout);
    freopen_s(&fStream, "conout$", "w", stderr);
}

VOID DbgPrintContext(PCONTEXT pContext, BOOL bDisas)
{
#if _WIN64
    DbgMsg("[+] rax= " HEX_FORMAT " rbx= " HEX_FORMAT " rcx= " HEX_FORMAT "\n", pContext->Rax, pContext->Rbx, pContext->Rcx);
    DbgMsg("[+] rdx= " HEX_FORMAT " rsi= " HEX_FORMAT " rdi= " HEX_FORMAT "\n", pContext->Rdx, pContext->Rsi, pContext->Rdi);
    DbgMsg("[+] rip= " HEX_FORMAT " rsp= " HEX_FORMAT " rbp= " HEX_FORMAT "\n", pContext->Rip, pContext->Rsp, pContext->Rbp);
    DbgMsg("[+]  r8= " HEX_FORMAT "  r9= " HEX_FORMAT " r10= " HEX_FORMAT "\n", pContext->R8, pContext->R9, pContext->R10);
    DbgMsg("[+] r11= " HEX_FORMAT " r12= " HEX_FORMAT " r13= " HEX_FORMAT "\n", pContext->R11, pContext->R12, pContext->R13);
    DbgMsg("[+] r14= " HEX_FORMAT " r15= " HEX_FORMAT "\n", pContext->R14, pContext->R15);
#else
    DbgMsg("[+] eax= " HEX_FORMAT " ebx= " HEX_FORMAT " ecx= " HEX_FORMAT " edx= " HEX_FORMAT " esi= " HEX_FORMAT " edi= " HEX_FORMAT "\n", pContext->Eax, pContext->Ebx, pContext->Ecx, pContext->Edx, pContext->Esi, pContext->Edi);
    DbgMsg("[+] eip= " HEX_FORMAT " esp= " HEX_FORMAT " ebp= " HEX_FORMAT "\n", pContext->Eip, pContext->Esp, pContext->Ebp);
#endif
    DbgMsg("[+] dr0= " HEX_FORMAT " dr1= " HEX_FORMAT " dr2= " HEX_FORMAT "\n", pContext->Dr0, pContext->Dr1, pContext->Dr2);
    DbgMsg("[+] dr3= " HEX_FORMAT " dr6= " HEX_FORMAT " dr7= " HEX_FORMAT "\n", pContext->Dr3, pContext->Dr6, pContext->Dr7);
    if (bDisas == TRUE) {
        #if _WIN64
        DisasOne((PBYTE)pContext->Rip, pContext->Rip, NULL);
        #else
        DisasOne((PBYTE)pContext->Eip, pContext->Eip, NULL);
        #endif
        DbgMsg("---\n");
    }
}

VOID DbgMsg(const char* szFormat, ...)
{
    static INT iInit = 0;
    va_list args;
    static FILE *fFp = NULL;
    static HANDLE hFile = INVALID_HANDLE_VALUE;
    
    //return;
    
    //va_start(args, szFormat);
    //memset(cpBuffer, 0, sizeof (cpBuffer));
    //vsprintf_s(cpBuffer, sizeof (cpBuffer) - 1, szFormat, args);
    //va_end(args);
    //printf("%s", cpBuffer);
    //return

    InitCriticalSection();
    EnterCriticalSection(&CriticalSection);
    va_start(args, szFormat);
    memset(cpBuffer, 0, sizeof (cpBuffer));
    vsprintf_s(cpBuffer, sizeof (cpBuffer) - 1, szFormat, args);
    va_end(args);
    if (!iInit) {
        GetCurrentDirectory(MAX_PATH - 1, bCurDir);
        sprintf_s(REAL_DBG_PATH, "%s\\%d_%s", bCurDir, GetCurrentProcessId(), FILE_DBG);
        //fopen_s(&fFp, REAL_DBG_PATH, "w");
        // hFile = CreateFileA(REAL_DBG_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
        hFile = CreateFileA(REAL_DBG_PATH, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("[-] CreateFileA(\"%s\", ...) failed : %lu\n", REAL_DBG_PATH, GetLastError());
            system("pause");
            ExitProcess(42);
        }
        iInit = 1;
    }
    //else {
    //    fopen_s(&fFp, REAL_DBG_PATH, "a");
    //}
    if (hFile != NULL) {
        //fprintf(fFp, "%s", cpBuffer);
        ////fflush(fFp);
        //fclose(fFp);
        DWORD lpNumberOfBytesWritten;
        WriteFile(hFile, cpBuffer, (DWORD)strlen(cpBuffer), &lpNumberOfBytesWritten, NULL);
    }
    printf("%s", cpBuffer);
    LeaveCriticalSection(&CriticalSection);
}

VOID Write2File(PVOID data, SSIZE_T size)
{
    static INT iInit = 0;
    FILE *fFpbin = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    
    InitCriticalSection();
    EnterCriticalSection(&CriticalSection);
    if (!iInit) {
        GetCurrentDirectory(MAX_PATH - 1, bCurDir);
        sprintf_s(REAL_DBG_PATH_BIN, "%s\\%s", bCurDir, "dump_dbg.bin");
        //fopen_s(&fFpbin, REAL_DBG_PATH_BIN, "wb");
        hFile = CreateFile(REAL_DBG_PATH_BIN, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
        iInit = 1;
    }
    else {
        fopen_s(&fFpbin, REAL_DBG_PATH_BIN, "ab");
    }
    if (fFpbin != NULL) {
        //fwrite(data, size, 0x01, fFpbin);
        //fprintf(fFp, "%s", cpBuffer);
        //fflush(fFp);
        //fclose(fFpbin);
        DWORD lpNumberOfBytesWritten;
        WriteFile(hFile, data, (DWORD)size, &lpNumberOfBytesWritten, NULL);
    }
    //printf("%s", cpBuffer);
    LeaveCriticalSection(&CriticalSection);
}

VOID HexDump(PVOID data, SSIZE_T size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    SSIZE_T n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    //EnterCriticalSection(&CriticalSection);
    //Write2File(data, size);
    //return;
    
    for (n = 1; n <= size; n++) {
        if (n % 16 == 1) {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", (unsigned int)((ULONG_PTR)p - (ULONG_PTR)data));
        }
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - strlen(charstr) - 1);
        if (n % 16 == 0) {
            DbgMsg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            //printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0) {
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr)-strlen(hexstr)-1);
        }
        p++;
    }
    if (strlen(hexstr) > 0) {
        DbgMsg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
        //printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    //LeaveCriticalSection(&CriticalSection);
}

VOID HexDumpPrintf(PVOID data, SSIZE_T size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    SSIZE_T n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    //EnterCriticalSection(&CriticalSection);
    //Write2File(data, size);
    //return;
    
    for (n = 1; n <= size; n++) {
        if (n % 16 == 1) {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", (unsigned int)((ULONG_PTR)p - (ULONG_PTR)data));
        }
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - strlen(charstr) - 1);
        if (n % 16 == 0) {
            //DbgMsg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0) {
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr)-strlen(hexstr)-1);
        }
        p++;
    }
    if (strlen(hexstr) > 0) {
        //DbgMsg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    //LeaveCriticalSection(&CriticalSection);
}

VOID PrintExportEntry(std::list<PEXPORTENTRY> lExport)
{
    std::list<PEXPORTENTRY>::const_iterator it;

#if _WIN64
    DbgMsg("Name                                               FunctionVA         FunctionRVA Ordinal\n");
    DbgMsg("================================================== ================== =========== =========\n");
#else
    DbgMsg("Name                                               FunctionVA FunctionRVA Ordinal\n");
    DbgMsg("================================================== ========== =========== =========\n");
#endif
    for (it = lExport.begin(); it != lExport.end(); ++it) {
        DbgMsg("%-50s " HEX_FORMAT " 0x%08X  0x%04X\n", (*it)->FunctionName, (*it)->FunctionVA, (*it)->FunctionRVA, (*it)->Ordinal);
    }
}

VOID PrintModuleInfo(VOID)
{
    std::list<PMODULE>::const_iterator it;

#if _WIN64
    DbgMsg("Name                           ModuleBase         ModuleSize NbExports\n");
    DbgMsg("============================== ================== ========== =========\n");
#else
    DbgMsg("Name                           ModuleBase ModuleSize NbExports\n");
    DbgMsg("============================== ========== ========== =========\n");
#endif
    for (it = pinfo.lModule.begin(); it != pinfo.lModule.end(); ++it) {
        DbgMsg("%-30s " HEX_FORMAT " 0x%08X %d\n", (*it)->szModule, (*it)->modBaseAddr, (*it)->modBaseSize, (*it)->lExport.size());
    }
#if _WIN64
    DbgMsg("============================== ================== ========== =========\n");
#else
    DbgMsg("============================== ========== ========== =========\n");
#endif
}

VOID PrintPeInfo(VOID)
{
    DbgMsg("[+] PID                : 0x%08X (%d)\n", GetCurrentProcessId(), GetCurrentProcessId());
    DbgMsg("[+] ModuleBase         : " HEX_FORMAT "\n", pinfo.ModuleBase);
    DbgMsg("[+] ModuleSize         : 0x%08X (%d)\n", pinfo.ModuleSize, pinfo.ModuleSize);
    DbgMsg("[+] ModuleNbSections   : 0x%08X (%d)\n", pinfo.ModuleNbSections, pinfo.ModuleNbSections);
    DbgMsg("[+] RVA EntryPoint     : 0x%08X\n", pinfo.EntryPoint);
}

VOID PrintInfoImporter(PIMPORTER Importer)
{
    std::list<PMODULE>::const_iterator it;

    DbgMsg("[+] nb modules : 0x%08X (%d)\n", Importer->lModule.size(), Importer->lModule.size());
    for (it = Importer->lModule.begin(); it != Importer->lModule.end(); ++it) {
        DbgMsg("[+] %-30s has 0x%08X (%d) API\n", (*it)->szModule, (*it)->lExport.size(), (*it)->lExport.size());
    }
}