# Test Hook

DLL example in order to test Hooking functionnality

A simple MessageBoxA example can be found [here][simple_32_64]

## IAT Hook

Use the `SetupIATHook` function from `hookstuff`:

    BOOL SetupIATHook(ULONG_PTR BaseAddress, LPCSTR ModName, LPCSTR ProcName, PROC pfnNew);

The callback function must follow the following declaration:

    VOID CallBackHook(PPUSHED_REGS pRegs);

Definition of structur `PPUSHED_REGS` can be found in [hookstuff.h][hookstuff_h]

## Inline Hook

Use the `SetupInlineHook` function from `hookstuff`:

    BOOL SetupInlineHook(LPCSTR ModName, LPCSTR ProcName, PROC pfnNew);
    BOOL SetupInlineHook(ULONG_PTR Addr, PROC pfnNew);

You can put inline hook at the entry of an exported function by a module or at an given address.

The callback function must follow the following declaration:

    VOID CallBackHook(PPUSHED_REGS pRegs);

Definition of structur `PPUSHED_REGS` can be found in [hookstuff.h][hookstuff_h]

## Useful MACRO

* `GET_RETURN_ADDR(pRegs)`: To get the return address of the hooked function

[simple_32_64]: https://github.com/w4kfu/misc/tree/master/simple_32_64
[hookstuff_h]: https://github.com/w4kfu/hacnpx/blob/master/Toolz/Injected/src/hookstuff.cpp
