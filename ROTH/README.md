# Realm Of the Hauting

## Decompression (PSEUDO-C)

    snew = new;
    while (size > 0)
    {
        while (1)
        {
            r = *p++;
            if (r >= 0xF1)
                break;
            *(new++) = r;
            if (--size < 0)
                return snew;
        }
        nb = (r + 0x10) & 0xFF;
        val = *p++;
        memset(new, val, nb);
        new += nb;
        size = size - nb;
    }

## Files

### BACKDROP.RAW

Format:

    +0x00 :     FLAG            [WORD]
    +0x02 :     UNK_WORD_00     [WORD]
    +0x04 :     WIDTH           [WORD]
    +0x06 :     HEIGHT          [WORD]
    +0x08 :     DATA_Z          [BYTE] * FILESIZE - 8

### ICONS.ALL

Format:

    +0x00 :     POSITION        [DWORD] \__ * 0x79
    +0x04 :     UNK_DWORD_00    [DWORD] /

Format file entry:

    +0x00 :     FLAG            [WORD]
    +0x02 :     UNK_WORD_00     [WORD]
    +0x04 :     WIDTH           [WORD]
    +0x06 :     HEIGHT          [WORD]
    +0x08 :     DATA_Z          [BYTE]
