#include "memory.h"

BOOL IsBadReadMemory(PVOID ptr, DWORD size)
{
    SIZE_T ret;
    MEMORY_BASIC_INFORMATION mbi;
    BOOL ok;

    (void)size;
    ret = VirtualQuery(ptr, &mbi, sizeof(mbi));
    if (ret == 0) {
        return TRUE;
    }
    ok = ((mbi.Protect & PAGE_READONLY) ||
        (mbi.Protect & PAGE_READWRITE) ||
        (mbi.Protect & PAGE_WRITECOPY) ||
        (mbi.Protect & PAGE_EXECUTE_READ) ||
        (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
        (mbi.Protect & PAGE_EXECUTE_WRITECOPY));
    if (mbi.Protect & PAGE_GUARD)
        return TRUE;
    if (mbi.Protect & PAGE_NOACCESS)
        return TRUE;
    return !ok;
}