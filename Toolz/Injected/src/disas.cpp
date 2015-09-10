#include "disas.h"

VOID DisasOne(PBYTE bCode, ULONG_PTR dwAddr, LPCSTR Modname)
{
    csh handle;
    cs_insn *insn;
    size_t count;

#if _WIN64
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
#else
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
#endif
        DbgMsg("[-] DisasAt - cs_open() failed\n");
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, bCode, 0x20, dwAddr, 0, &insn);
    if (count > 0) {
        PrintInstru(Modname, insn[0].address, insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
    }
    else
        DbgMsg("ERROR: Failed to disassemble given code!\n");
    cs_close(&handle);
}

VOID DisasAt(PBYTE bCode, DWORD dwSize, ULONG_PTR dwAddr, LPCSTR Modname)
{
    csh handle;
    cs_insn *insn;
    size_t count;
    size_t j;

#if _WIN64
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
#else
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
#endif
        DbgMsg("[-] DisasAt - cs_open() failed\n");
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, bCode, dwSize, dwAddr, 0, &insn);
    if (count > 0) {
        for (j = 0; j < count; j++) {
            PrintInstru(Modname, insn[j].address, insn[j].mnemonic, insn[j].op_str);
            //if (Modname)
            //    DbgMsg("%s:0x%016llX:\t%s\t%s\n", Modname, insn[j].address, insn[j].mnemonic, insn[j].op_str);
            //else
            //    DbgMsg("0x%016llX:\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
        }
        //if (Modname)
        //    DbgMsg("%s:0x%016llX:\n", Modname, insn[j - 1].address + insn[j - 1].size);
        //else
        //    DbgMsg("0x%016llX:\n", insn[j - 1].address + insn[j - 1].size);
        cs_free(insn, count);
    }
    else
        DbgMsg("ERROR: Failed to disassemble given code!\n");
    cs_close(&handle);
}