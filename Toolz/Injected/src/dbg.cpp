#include "dbg.h"

extern PE_INFO pinfo;
CHAR REAL_DBG_PATH[512] = {0};
CHAR cpBuffer[512];
CHAR bCurDir[512] = {0};

VOID MakeConsole(VOID)
{
    DWORD dwMode;
    struct _CONSOLE_SCREEN_BUFFER_INFO sbi;
    HANDLE hStd;
    FILE *fStream;

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

VOID DbgMsg(const char* szFormat, ...)
{
    static INT iInit = 0;
    va_list args;
    FILE *fFp = NULL;

    va_start(args, szFormat);
    memset(cpBuffer, 0, sizeof (cpBuffer));
    vsprintf_s(cpBuffer, sizeof (cpBuffer) - 1, szFormat, args);
    va_end(args);
    if (!iInit) {
        GetCurrentDirectory(MAX_PATH - 1, bCurDir);
        sprintf_s(REAL_DBG_PATH, "%s\\%s", bCurDir, FILE_DBG);
        fopen_s(&fFp, REAL_DBG_PATH, "w");
        iInit = 1;
    }
    else {
        fopen_s(&fFp, REAL_DBG_PATH, "a");
    }
    if (fFp != NULL) {
        fprintf(fFp, "%s", cpBuffer);
        fclose(fFp);
    }
    printf("%s", cpBuffer);
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

    for (n = 1; n <= size; n++) {
        if (n % 16 == 1) {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", ((unsigned int)p - (unsigned int)data));
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
    }
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
        DbgMsg("%-50s "HEX_FORMAT" 0x%08X  0x%04X\n", (*it)->FunctionName, (*it)->FunctionVA, (*it)->FunctionRVA, (*it)->Ordinal);
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
        DbgMsg("%-30s "HEX_FORMAT" 0x%08X %d\n", (*it)->szModule, (*it)->modBaseAddr, (*it)->modBaseSize, (*it)->lExport.size());
    }
#if _WIN64
    DbgMsg("============================== ================== ========== =========\n");
#else
    DbgMsg("============================== ========== ========== =========\n");
#endif
}

VOID PrintPeInfo(VOID)
{
    DbgMsg("[+] ModuleBase         : "HEX_FORMAT"\n", pinfo.ModuleBase);
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