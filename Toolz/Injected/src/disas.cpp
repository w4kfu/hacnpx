#include "disas.h"

csh caphandle = 0x00;

VOID InitCap(VOID)
{
    if (caphandle == 0x00) {
    #if _WIN64
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &caphandle) != CS_ERR_OK) {
    #else
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &caphandle) != CS_ERR_OK) {
    #endif
            DbgMsg("[-] InitCap - cs_open() failed\n");
            ExitProcess(42);
        }
    }
    cs_option(caphandle, CS_OPT_DETAIL, CS_OPT_ON);
}

BOOL GetJmpIndirect(PBYTE bCode, ULONG_PTR *Dst)
{
    cs_insn *insn;
    size_t count;
    BOOL bRet = FALSE;
    
    InitCap();
    count = cs_disasm(caphandle, bCode, 0x20, (ULONG_PTR)bCode, 0, &insn);
    if (count > 0) {
        //PrintInstru(0x00, insn[0].address, insn[0].mnemonic, insn[0].op_str);
        //DbgMsg("0x%016llX    %s    %s\n", insn[0].address, insn[0].mnemonic, insn[0].op_str);
        if (insn[0].id == X86_INS_JMP) {
            if (insn[0].detail->x86.operands[0].type == X86_OP_MEM) {
                #if _WIN64
                    if (insn[0].detail->x86.operands[0].mem.base == X86_REG_RIP) {
                        //DbgMsg("[+] GetJmpIndirect OK!\n");
                        DWORD64 d = (ULONG_PTR)bCode + insn[0].detail->x86.operands[0].mem.disp + insn[0].size;
                        //DbgMsg("[+] DST = [0x%016llX] : 0x%016llX\n", d, *(DWORD64*)d);
                        *Dst = *(DWORD64*)d;
                        bRet = TRUE;
                    }
                #else
                    //DbgMsg("[+] GetJmpIndirect OK!\n");
                    DWORD d = insn[0].detail->x86.operands[0].mem.disp;
                    //DbgMsg("[+] DST = [0x%08X] : 0x%08X\n", d, *(DWORD*)d);
                    *Dst = *(DWORD*)d;
                    bRet = TRUE;
                #endif
            }
            else {
                *Dst = insn[0].detail->x86.operands[0].imm;
                bRet = TRUE;
            }
        }
        cs_free(insn, count);
        return bRet;
    }
    else {
        DbgMsg("[-] ERROR: Failed to disassemble given code!\n");
    }
    return bRet;
}

int DisasLength(PBYTE bCode)
{
    cs_insn *insn;
    size_t count;
    int size = 0x00;

    InitCap();
    count = cs_disasm(caphandle, bCode, 0x20, 0x00, 0, &insn);
    if (count > 0) {
        size = insn[0].size;
        cs_free(insn, count);
        return size;
    }
    else {
        DbgMsg("[-] ERROR: Failed to disassemble given code!\n");
    }
    return 0x00;
}

VOID DisasOne(PBYTE bCode, ULONG_PTR dwAddr, LPCSTR Modname)
{
    cs_insn *insn;
    size_t count;

    InitCap();
    count = cs_disasm(caphandle, bCode, 0x20, dwAddr, 0, &insn);
    if (count > 0) {
        PrintInstru(Modname, insn[0].address, insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
    else {
        DbgMsg("ERROR: Failed to disassemble given code!\n");
    }
}

VOID DisasOneAndReg(PBYTE bCode, ULONG_PTR dwAddr, LPCSTR Modname, PCONTEXT ContextRecord)
{
    cs_insn *insn;
    size_t count;
    cs_regs regs_read, regs_write;
    uint8_t read_count, write_count, i;

    InitCap();
    count = cs_disasm(caphandle, bCode, 0x20, dwAddr, 0, &insn);
    if (count > 0) {
        PrintInstru(Modname, insn[0].address, insn[0].mnemonic, insn[0].op_str);
        if (cs_regs_access(caphandle, &insn[0], regs_read, &read_count, regs_write, &write_count) == 0) {
            if (read_count > 0) {
                for (i = 0; i < read_count; i++) {
                    switch (regs_read[i]) {
                        #if _WIN64
                        case X86_REG_RAX:
                            DbgMsg("[+] RAX : " HEX_FORMAT "\n", ContextRecord->Rax);
                            break;
                        case X86_REG_RBX:
                            DbgMsg("[+] RBX : " HEX_FORMAT "\n", ContextRecord->Rbx);
                            break;
                        case X86_REG_RCX:
                            DbgMsg("[+] RCX : " HEX_FORMAT "\n", ContextRecord->Rcx);
                            break;
                        case X86_REG_RDX:
                            DbgMsg("[+] RDX : " HEX_FORMAT "\n", ContextRecord->Rdx);
                            break;
                        case X86_REG_RDI:
                            DbgMsg("[+] RDI : " HEX_FORMAT "\n", ContextRecord->Rdi);
                            break;
                        case X86_REG_RSI:
                            DbgMsg("[+] RSI : " HEX_FORMAT "\n", ContextRecord->Rsi);
                            break;
                        #else
                        case X86_REG_EAX:
                            DbgMsg("[+] EAX : " HEX_FORMAT "\n", ContextRecord->Eax);
                            break;
                        case X86_REG_EBX:
                            DbgMsg("[+] EBX : " HEX_FORMAT "\n", ContextRecord->Ebx);
                            break;
                        case X86_REG_ECX:
                            DbgMsg("[+] ECX : " HEX_FORMAT "\n", ContextRecord->Ecx);
                            break;
                        case X86_REG_EDX:
                            DbgMsg("[+] EDX : " HEX_FORMAT "\n", ContextRecord->Edx);
                            break;
                        case X86_REG_EDI:
                            DbgMsg("[+] EDI : " HEX_FORMAT "\n", ContextRecord->Edi);
                            break;
                        case X86_REG_ESI:
                            DbgMsg("[+] ESI : " HEX_FORMAT "\n", ContextRecord->Esi);
                            break;
                        #endif
                    }
                }
            }
            if (write_count > 0) {
                for (i = 0; i < write_count; i++) {
                    switch (regs_write[i]) {
                        #if _WIN64
                        case X86_REG_RAX:
                            DbgMsg("[+] RAX : " HEX_FORMAT "\n", ContextRecord->Rax);
                            break;
                        case X86_REG_RBX:
                            DbgMsg("[+] RBX : " HEX_FORMAT "\n", ContextRecord->Rbx);
                            break;
                        case X86_REG_RCX:
                            DbgMsg("[+] RCX : " HEX_FORMAT "\n", ContextRecord->Rcx);
                            break;
                        case X86_REG_RDX:
                            DbgMsg("[+] RDX : " HEX_FORMAT "\n", ContextRecord->Rdx);
                            break;
                        case X86_REG_RDI:
                            DbgMsg("[+] RDI : " HEX_FORMAT "\n", ContextRecord->Rdi);
                            break;
                        case X86_REG_RSI:
                            DbgMsg("[+] RSI : " HEX_FORMAT "\n", ContextRecord->Rsi);
                            break;
                        #else
                        case X86_REG_EAX:
                            DbgMsg("[+] EAX : " HEX_FORMAT "\n", ContextRecord->Eax);
                            break;
                        case X86_REG_EBX:
                            DbgMsg("[+] EBX : " HEX_FORMAT "\n", ContextRecord->Ebx);
                            break;
                        case X86_REG_ECX:
                            DbgMsg("[+] ECX : " HEX_FORMAT "\n", ContextRecord->Ecx);
                            break;
                        case X86_REG_EDX:
                            DbgMsg("[+] EDX : " HEX_FORMAT "\n", ContextRecord->Edx);
                            break;
                        case X86_REG_EDI:
                            DbgMsg("[+] EDI : " HEX_FORMAT "\n", ContextRecord->Edi);
                            break;
                        case X86_REG_ESI:
                            DbgMsg("[+] ESI : " HEX_FORMAT "\n", ContextRecord->Esi);
                            break;
                        #endif
                    }
                }
            }
        }
        cs_free(insn, count);
    }
    else {
        DbgMsg("ERROR: Failed to disassemble given code!\n");
    }
}

BOOL TestDisasAt(PBYTE bCode, DWORD dwSize, ULONG_PTR dwAddr, LPCSTR Modname)
{
    cs_insn *insn;
    size_t count;

    InitCap();
    count = cs_disasm(caphandle, bCode, dwSize, dwAddr, 0, &insn);
    if (count > 0) {
        cs_free(insn, count);
        return TRUE;
    }
    return FALSE;
}

BOOL DisasAt(PBYTE bCode, DWORD dwSize, ULONG_PTR dwAddr, LPCSTR Modname)
{
    cs_insn *insn;
    size_t count;
    size_t j;

    InitCap();
    count = cs_disasm(caphandle, bCode, dwSize, dwAddr, 0, &insn);
    if (count > 0) {
        for (j = 0; j < count; j++) {
            PrintInstru(Modname, insn[j].address, insn[j].mnemonic, insn[j].op_str);
            /* if (Modname)
                DbgMsg("%s:0x%016llX:\t%s\t%s\n", Modname, insn[j].address, insn[j].mnemonic, insn[j].op_str);
            else
                DbgMsg("0x%016llX:\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str); */
        }
        /* if (Modname)
            DbgMsg("%s:0x%016llX:\n", Modname, insn[j - 1].address + insn[j - 1].size);
        else
            DbgMsg("0x%016llX:\n", insn[j - 1].address + insn[j - 1].size); */
        cs_free(insn, count);
    }
    else {
        DbgMsg("ERROR: Failed to disassemble given code!\n");
        return FALSE;
    }
    return TRUE;
}