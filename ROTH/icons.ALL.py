import struct
import Image

# http://www.pythonware.com/products/pil/

class Buffer:
    def __init__(self, buf):
        self.buf = buf
        self.length = len(self.buf)
        self.pos = 0

    def GetByte(self):
        byte = struct.unpack("<B", self.buf[self.pos: self.pos + 1])[0]
        self.pos += 1
        return byte

    def GetWord(self):
        word = struct.unpack("<H", self.buf[self.pos: self.pos + 2])[0]
        self.pos += 2
        return word

    def GetDword(self):
        dword = struct.unpack("<I", self.buf[self.pos: self.pos + 4])[0]
        self.pos += 4
        return dword

    def GetQword(self):
        qword = struct.unpack("<Q", self.buf[self.pos: self.pos + 8])[0]
        self.pos += 8
        return qword

    def GetBuffer(self):
        size = self.GetDword()
        b = self.buf[self.pos:self.pos + size]
        self.pos += size
        return b

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')

def unstfu(b, size):
    res_buf = ""
    while size > 0:
        while True:
            r = b.GetByte()
            if r >= 0xF1:
                break
            res_buf += chr(r)
            size = size - 1
            if size <= 0:
                return res_buf
        nb = (r + 0x10) & 0xFF
        val = b.GetByte()
        res_buf += (chr(val) * nb)
        size = size - nb
    return res_buf

pal = [    0x000000, 0x0000A8, 0x00A800, 0x00A8A8, 0xA80000, 0xA800A8, 0xA85400, 0xA8A8A8,
    0x545454, 0x5454FC, 0x54FC54, 0x54FCFC, 0xFC5454, 0xFC54FC, 0xFCFC54, 0xFCFCFC,
    0xFCFCFC, 0xDCDCDC, 0xCCCCCC, 0xC0C0C0, 0xB0B0B0, 0xA4A4A4, 0x989898, 0x888888,
    0x7C7C7C, 0x707070, 0x606060, 0x545454, 0x484848, 0x383838, 0x2C2C2C, 0x202020,
    0xFCD8D8, 0xFCB8B8, 0xFC9C9C, 0xFC7C7C, 0xFC5C5C, 0xFC4040, 0xFC2020, 0xFC0000,
    0xE40000, 0xCC0000, 0xB40000, 0x9C0000, 0x840000, 0x700000, 0x580000, 0x400000,
    0xFCE8D8, 0xFCDCC0, 0xFCD4AC, 0xFCC894, 0xFCC080, 0xFCB868, 0xFCAC54, 0xFCA43C,
    0xFC9C28, 0xE08820, 0xC4781C, 0xA86414, 0x905410, 0x744008, 0x583004, 0x402000,
    0xFCFCD8, 0xFCFCB8, 0xFCFC9C, 0xFCFC7C, 0xFCF85C, 0xFCF440, 0xFCF420, 0xFCF400,
    0xE4D800, 0xCCC000, 0xB4A400, 0x9C8C00, 0x847400, 0x6C5800, 0x544000, 0x402800,
    0xF8FCD8, 0xF4FCB8, 0xE8FC9C, 0xE0FC7C, 0xD0FC5C, 0xC4FC40, 0xB4FC20, 0xA0FC00,
    0x90E400, 0x80CC00, 0x74B400, 0x609C00, 0x508400, 0x447000, 0x345800, 0x284000,
    0xD8FCD8, 0x9CFC9C, 0x90EC90, 0x84E084, 0x78D078, 0x70C46C, 0x64B864, 0x58A858,
    0x509C4C, 0x449040, 0x388034, 0x2C742C, 0x246820, 0x185814, 0x0C4C08, 0x044000,
    0xD8FCFC, 0xB8FCFC, 0x9CFCFC, 0x7CFCF8, 0x5CFCFC, 0x40FCFC, 0x20FCFC, 0x00FCFC,
    0x00E4E4, 0x00CCCC, 0x00B4B4, 0x009C9C, 0x008484, 0x007070, 0x005858, 0x004040,
    0xD8ECFC, 0xB8E0FC, 0x9CD4FC, 0x7CC8FC, 0x5CBCFC, 0x40B0FC, 0x009CFC, 0x008CE4,
    0x0080D0, 0x0074BC, 0x0064A8, 0x005890, 0x004C7C, 0x003C68, 0x003054, 0x002440,
    0xD8D8FC, 0xB8BCFC, 0x9C9CFC, 0x7C80FC, 0x5C60FC, 0x4040FC, 0x0004FC, 0x0000E4,
    0x0000D0, 0x0000BC, 0x0000A8, 0x000090, 0x00007C, 0x000068, 0x000054, 0x000040,
    0xF0D8FC, 0xE4B8FC, 0xD89CFC, 0xD07CFC, 0xC85CFC, 0xBC40FC, 0xB420FC, 0xA800FC,
    0x9800E4, 0x8000CC, 0x7400B4, 0x60009C, 0x500084, 0x440070, 0x340058, 0x280040,
    0xFCD8FC, 0xFCB8FC, 0xFC9CFC, 0xFC7CFC, 0xFC5CFC, 0xFC40FC, 0xFC20FC, 0xE000E4,
    0xCC00CC, 0xB800B8, 0xA400A4, 0x900090, 0x7C007C, 0x680068, 0x540054, 0x400040,
    0xFCE8DC, 0xF0D4C4, 0xE4C4AC, 0xD8B498, 0xCCA080, 0xC0906C, 0xB48054, 0xAC7040,
    0x9C6438, 0x8C5C34, 0x80542C, 0x704C28, 0x604020, 0x54381C, 0x443014, 0x382810,
    0xFCD8CC, 0xF8CCB8, 0xF4C0A8, 0xF0B494, 0xECA884, 0xE89C74, 0xE49464, 0xE08C58,
    0xD8804C, 0xD47840, 0xC86C34, 0xC0602C, 0xB45424, 0xA8481C, 0x9C3C14, 0x94300C,
    0xF4C0A8, 0xF0BCA0, 0xF0B89C, 0xF0B494, 0xECB090, 0xECAC88, 0xECA884, 0xE8A480,
    0xE8A078, 0xE89C74, 0xE4986C, 0xE49468, 0xE49464, 0xFC9C9C, 0xFC9494, 0xFC9090,
    0xFC8C8C, 0xFC8484, 0xFC8080, 0xFC7C7C, 0xD8B498, 0xD0AC8C, 0xCCA484, 0xC89C7C,
    0xC49474, 0xC0906C, 0xC0C0C0, 0xBCBCBC, 0xB8B8B8, 0xB4B4B4, 0xB0B0B0, 0xFFFFFF]

def handle_ico(b, pos, nb=0):
    b.pos = pos
    unk_byte_00 = b.GetByte()
    unk_byte_01 = b.GetByte()
    unk_byte_02 = b.GetByte()
    unk_byte_03 = b.GetByte()
    unk_word_00 = b.GetWord()
    unk_word_01 = b.GetWord()
    print "[+] unk_byte_00  = %02X" % unk_byte_00
    print "[+] unk_byte_01  = %02X" % unk_byte_01
    print "[+] unk_byte_02  = %02X" % unk_byte_02
    print "[+] unk_byte_03  = %02X" % unk_byte_03
    print "[+] unk_word_00  = %04X" % unk_word_00
    print "[+] unk_word_01  = %04X" % unk_word_01
    if unk_byte_00 & 0x01:
        res_buf = unstfu(b, unk_word_00 * unk_word_01)
        print hexdump(res_buf, unk_word_00)
        #i = Image.new("L", (unk_word_00, unk_word_01))
        #for x in xrange(0, unk_word_00):
            #for y in xrange(0, unk_word_01):
                #i.putpixel((x, y), ord(res_buf[x + y]))
        #i.pixel = res_buf
        new_buf = ""
        for i in xrange(0, len(res_buf)):
            new_buf += struct.pack("<I", pal[ord(res_buf[i])])
            #new_buf += chr((pal[ord(res_buf[i])] >> 16) & 0xFF) + chr((pal[ord(res_buf[i])] >> 8) & 0xFF) + chr((pal[ord(res_buf[i])]) & 0xFF)
        i = Image.frombuffer("RGB", (unk_word_00, unk_word_01), new_buf)
        i = i.transpose(Image.FLIP_TOP_BOTTOM)
        i.save("%d.jpg" % nb)
    else:
        print "STFU"

FILENAME = "ICONS.ALL"

b = Buffer(open(FILENAME, "rb").read())
for i in xrange(0, 0x79):
    pos = b.GetDword()
    unk_dword_00 = b.GetDword()
    print "[+] pos          = %08X" % pos
    print "[+] unk_dword_00 = %08X" % unk_dword_00
    save_pos = b.pos
    handle_ico(b, pos, i)
    b.pos = save_pos
