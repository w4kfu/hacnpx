#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define FILE_DBG "dbg_msg.txt"

void hex_dump(void *data, size_t size);
void dbg_msg(char *format, ...);

#endif // __DBG_H__