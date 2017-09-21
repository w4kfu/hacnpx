import sys
import os
import shutil
#from elfesteem import *
import pefile

def create_makefile(res_dir, makefile_name, fake_c_name, fake_asm_name, fake_dll, pe_filename):
    makefile = '''@cl.exe '''+fake_c_name+''' /W3 /GF /GS- /GA /MT /nologo /c /TC /DTRAMPO
@ml64.exe /DTRAMPO /c '''+fake_asm_name+'''
@link '''+os.path.splitext(fake_c_name)[0]+'''.obj '''+os.path.splitext(fake_asm_name)[0]+'''.obj /dll /release /subsystem:console /out:'''+fake_dll+''' /MACHINE:X64 /MANIFEST:NO /merge:.rdata=.text /def:'''+ os.path.splitext(pe_filename)[0] +'''.def
del *.obj
del *.exp
'''
    open(res_dir + makefile_name, "wb").write(makefile)

def create_fake_def(l_export, res_dir, fake_asm_name, pe_filename):
    fname = os.path.splitext(pe_filename)[0] + ".def"
    fd_out = open(res_dir + fname, "w")
    fd_out.write("EXPORTS\n")
    for name, virt in l_export:
        n = name.replace("?", "_")
        n = n.replace("@", "_")
        fd_out.write("%s=%s\n" % (name, os.path.splitext(fake_asm_name)[0]+"_"+n))
    
    
def create_fake_asm(l_export, res_dir, fake_asm_name):
    asm_head = '''.data

save_return_addr    dq 0
save_rcx            dq 0

.code

PUSHAQ MACRO 
    push rax        ; + 0x08
    push rbx        ; + 0x10
    push rcx        ; + 0x18
    push rdx        ; + 0x20
    push rbp        ; + 0x28
    push rdi        ; + 0x30
    push rsi        ; + 0x40
    push r8         ; + 0x48
    push r9         ; + 0x50
    push r10        ; + 0x58
    push r11        ; + 0x60
    push r12        ; + 0x68
    push r13        ; + 0x70
    push r14        ; + 0x78
    push r15        ; + 0x80
ENDM

POPAQ MACRO 
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9 
    pop r8 
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
ENDM

'''
    fd_out = open(res_dir + fake_asm_name, "w")
    fd_out.write(asm_head)
    for name, virt in l_export:
        n = name.replace("?", "_")
        n = n.replace("@", "_")
        fd_out.write("EXTERN Before_%s:PROC\nEXTERN After_%s:PROC\nIFDEF TRAMPO\nEXTERN Real_%s:QWORD\nENDIF\n" % (n, n, n))
    fd_out.write("\n\n")
    for name, virt in l_export:
        n = name.replace("?", "_")
        n = n.replace("@", "_")
        #buf = os.path.splitext(fake_asm_name)[0]+"_"+name+''' PROC EXPORT
        buf = os.path.splitext(fake_asm_name)[0]+"_"+n+''' PROC
        
    IFDEF TRAMPO

    PUSHAQ
    mov     rcx, rsp
    sub     rsp, 20h
    call    Before_'''+n+'''
    add     rsp, 20h
    POPAQ
    
    mov     rax, [rsp]
    mov     save_return_addr, rax
    add     rsp, 8
    call    qword ptr [Real_'''+n+''']
    sub     rsp, 8
    mov     [rsp - 8], rax
    mov     rax, save_return_addr
    mov     [rsp], rax
    mov     rax, [rsp - 8]

    PUSHAQ
    mov     rcx, rsp
    sub     rsp, 20h
    call    After_'''+n+'''
    add     rsp, 20h
    POPAQ

    ELSE
    
    xor     rax, rax

    ENDIF
    
    ret
    
'''+os.path.splitext(fake_asm_name)[0]+"_"+n+''' ENDP\n\n'''
        fd_out.write(buf)
    fd_out.write("\n\nend\n")
    fd_out.close()

def create_fake_c(l_export, res_dir, fake_c_name, original_dll):
    real_out = ""
    real_getproc = ""
    for name, virt in l_export:
        n = name.replace("?", "_")
        n = n.replace("@", "_")
        real_out += "FARPROC Real_%s;\n" % n
        real_getproc += 'Real_%s = GetProcAddress(hModuleOriginal, "%s");\n' % (n, name)
    real_c = '''#if TRAMPO
'''+real_out+'''
VOID LoadAllRealExport(HMODULE hModuleOriginal)
{
'''+real_getproc+'''
}
#endif
'''

    fake_c = '''#include <windows.h>
#include <stdio.h>
#include <ctype.h>

#define FILE_DBG "dbg_msg_DLL.txt"

struct all_reg_64
{
    DWORD64 r15;
    DWORD64 r14;
    DWORD64 r13;
    DWORD64 r12;
    DWORD64 r11;
    DWORD64 r10;
    DWORD64 r9;
    DWORD64 r8;
    DWORD64 rsi;
    DWORD64 rdi;
    DWORD64 rbp;
    DWORD64 rdx;
    DWORD64 rcx;
    DWORD64 rbx;
    DWORD64 rax;
};

PVOID protVectoredHandler = NULL;

#if _WIN64
    #define HEX_FORMAT "0x%016llX"
#else
    #define HEX_FORMAT "0x%08X"
#endif

VOID DbgPrintContext(PCONTEXT pContext, BOOL bDisas)
{
#if _WIN64
    printf("[+] rax= " HEX_FORMAT " rbx= " HEX_FORMAT " rcx= " HEX_FORMAT "\\n", pContext->Rax, pContext->Rbx, pContext->Rcx);
    printf("[+] rdx= " HEX_FORMAT " rsi= " HEX_FORMAT " rdi= " HEX_FORMAT "\\n", pContext->Rdx, pContext->Rsi, pContext->Rdi);
    printf("[+] rip= " HEX_FORMAT " rsp= " HEX_FORMAT " rbp= " HEX_FORMAT "\\n", pContext->Rip, pContext->Rsp, pContext->Rbp);
    printf("[+]  r8= " HEX_FORMAT "  r9= " HEX_FORMAT " r10= " HEX_FORMAT "\\n", pContext->R8, pContext->R9, pContext->R10);
    printf("[+] r11= " HEX_FORMAT " r12= " HEX_FORMAT " r13= " HEX_FORMAT "\\n", pContext->R11, pContext->R12, pContext->R13);
    printf("[+] r14= " HEX_FORMAT " r15= " HEX_FORMAT "\\n", pContext->R14, pContext->R15);
#else
    printf("[+] eax= " HEX_FORMAT " ebx= " HEX_FORMAT " ecx= " HEX_FORMAT " edx= " HEX_FORMAT " esi= " HEX_FORMAT " edi= " HEX_FORMAT "\\n", pContext->Eax, pContext->Ebx, pContext->Ecx, pContext->Edx, pContext->Esi, pContext->Edi);
    printf("[+] eip= " HEX_FORMAT " esp= " HEX_FORMAT " ebp= " HEX_FORMAT "\\n", pContext->Eip, pContext->Esp, pContext->Ebp);
#endif
    printf("[+] dr0= " HEX_FORMAT " dr1= " HEX_FORMAT " dr2= " HEX_FORMAT "\\n", pContext->Dr0, pContext->Dr1, pContext->Dr2);
    printf("[+] dr3= " HEX_FORMAT " dr6= " HEX_FORMAT " dr7= " HEX_FORMAT "\\n", pContext->Dr3, pContext->Dr6, pContext->Dr7);
}


LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    ULONG_PTR BaseOfImage;
    BYTE Filename[0x200];

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0x40010006) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == 0x406D1388) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    printf("[+] ExceptionInfo->ExceptionRecord->ExceptionCode : 0x%08X\\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    DbgPrintContext(ExceptionInfo->ContextRecord, TRUE);
    return EXCEPTION_CONTINUE_SEARCH;
}

int init = 0;

void dbg_msg(char *format, ...)
{
    char buffer[512];
    va_list args;
    FILE *fp = NULL;

    va_start(args, format);
    memset(buffer, 0, sizeof (buffer));
    vsprintf_s(buffer, 512, format, args);
    if (!init)
    {
        fopen_s(&fp, FILE_DBG, "w");
        init = 1;
    }
    else
    {
        fopen_s(&fp, FILE_DBG, "a");
    }
    va_end(args);
    fprintf(fp, "%s", buffer);
    printf("%s", buffer);
    fclose(fp);
}

void hexdump(void *data, int size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for (n = 1; n <= size; n++)
    {
        if (n % 16 == 1)
        {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", ((unsigned int)p - (unsigned int)data));
        }
        c = *p;
        if (isprint(c) == 0)
        {
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - strlen(charstr) - 1);
        if (n % 16 == 0)
        {
            dbg_msg("[%4.4s]   %-50.50s  %s\\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0)
        {
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr)-strlen(hexstr)-1);
        }
        p++;
    }

    if (strlen(hexstr) > 0)
    {
        dbg_msg("[%4.4s]   %-50.50s  %s\\n", addrstr, hexstr, charstr);
    }
}

'''+real_c+'''

#if TRAMPO

#define ORIGINAL_DLL_NAME "'''+original_dll+'''"

VOID LoadRealExport(VOID)
{
        HMODULE hModuleOriginal;

    hModuleOriginal = LoadLibraryA(ORIGINAL_DLL_NAME);
    if (hModuleOriginal == NULL)
    {
        dbg_msg("[-] LoadLibraryA(%s) failed : %u\\n", ORIGINAL_DLL_NAME, GetLastError());
        return;
    }
    dbg_msg("[+] Original DLL : 0x%016llX\\n", hModuleOriginal);
    LoadAllRealExport(hModuleOriginal);
}

#endif

VOID PrintInfoReg(struct all_reg_64 *reg, BOOL Head)
{
    MEMORY_BASIC_INFORMATION64 mbi = {0};

    if (Head == TRUE)
    {
        dbg_msg("[+] rcx : 0x%016llX\\n", reg->rcx);
        dbg_msg("[+] rdx : 0x%016llX\\n", reg->rdx);
        dbg_msg("[+] r8  : 0x%016llX\\n", reg->r8);
        dbg_msg("[+] r9  : 0x%016llX\\n", reg->r9);
    }
    else
    {
        dbg_msg("------\\n");
        dbg_msg("[+] rax : 0x%016llX\\n", reg->rax);
        if (!VirtualQuery((LPCVOID)reg->rax, (PMEMORY_BASIC_INFORMATION)&mbi, sizeof (MEMORY_BASIC_INFORMATION64)))
        {
            dbg_msg("[-] VirtualQuery failed : %u\\n", GetLastError());
        }
        else
        {
            if (mbi.State & MEM_COMMIT)
            {
                dbg_msg("[+] size ? : %X\\n", mbi.RegionSize);
                hexdump((char*)reg->rax, 0x100);
            }
        }
    }
}

VOID PrintHead(LPCSTR FuncName)
{
    dbg_msg("#########################################################\\n");
    dbg_msg("[+] FuncName : %s\\n", FuncName);
}

VOID PrintBottom(VOID)
{
    dbg_msg("#########################################################\\n\\n");
}

VOID MakeConsole(VOID)
{
    FILE *stream;
    
    AllocConsole();
    freopen_s(&stream, "CONIN$", "rb", stdin);
    freopen_s(&stream, "CONOUT$", "wb", stdout);
    freopen_s(&stream, "CONOUT$", "wb", stderr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HMODULE hModule;
    
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        protVectoredHandler = AddVectoredExceptionHandler(0x1, ProtectionFaultVectoredHandler);
        MakeConsole();
        hModule = GetModuleHandleA(NULL);
        DisableThreadLibraryCalls(hModule);
        dbg_msg("[+] hModule = 0x%016llX\\n", hModule);
        
        #if TRAMPO
        
        LoadRealExport();
        
        #endif
    }
    return TRUE;
}
'''
    open(res_dir + fake_c_name, "wb").write(fake_c)

def append_fake_export(l_export, res_dir, fake_c_name):
    fd_out = open(res_dir + fake_c_name, "a")
    for name, virt in l_export:
        n = name.replace("?", "_")
        n = n.replace("@", "_")
        buf = '''void Before_'''+n+'''(struct all_reg_64 *reg)
{
    PrintHead("'''+name+'''");
    PrintInfoReg(reg, TRUE);
}

void After_'''+n+'''(struct all_reg_64 *reg)
{
    PrintInfoReg(reg, FALSE);
    PrintBottom();
}

'''
        fd_out.write(buf)
    fd_out.close()

def createdir(dirname):
    try:
        os.stat(dirname)
    except:
        os.mkdir(dirname)

def get_export_name_addr_list(e):
    out = []
    for export in e.DIRECTORY_ENTRY_EXPORT.symbols:
        if export.address is not None:
            name = "None"
            if not export.name:
                raise ValueError("[-] meh :(")
            else:
                name = export.name
        out.append((name, export.address))
    return out

if __name__ == '__main__':        
    if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
        print "[-] Usage: mitm_dll.py <DLL>\n"
        sys.exit()
    else:
        pe_filename = sys.argv[1]
        pe = pefile.PE(pe_filename)
        l_export = get_export_name_addr_list(pe)
        for name, virt in l_export:
            print name
        pe_filename = os.path.splitext(pe_filename)[0]
        makefile_name = "make.bat"
        res_dir = pe_filename + "_res_dir/"
        fake_c_name = pe_filename + ".c"
        fake_asm_name = pe_filename + "_trampo.asm"
        fake_dll = pe_filename + ".dll"
        original_dll = pe_filename + "_original.dll"
        createdir(res_dir)
        create_makefile(res_dir, makefile_name, fake_c_name, fake_asm_name, fake_dll, pe_filename)
        create_fake_asm(l_export, res_dir, fake_asm_name)
        shutil.copyfile(sys.argv[1], res_dir + original_dll)
        create_fake_c(l_export, res_dir, fake_c_name, original_dll)
        append_fake_export(l_export, res_dir, fake_c_name)
        create_fake_def(l_export, res_dir, fake_asm_name, pe_filename)
