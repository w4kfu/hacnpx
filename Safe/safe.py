import construct
from elfesteem import *

safeInfo = construct.Struct("safeInfo",
                construct.String("signature", 20),
                construct.ULInt32("unk_dword_00"),
                construct.ULInt32("unk_dword_01"),
                construct.ULInt32("unk_dword_02"),
                construct.ULInt32("version"),
                construct.ULInt32("subversion"),
                construct.ULInt32("revision")
                )

safeEntry = construct.Struct("safeEntry",
                construct.ULInt32("unk_dword_00"),
                construct.ULInt32("unk_dword_01"),
                construct.ULInt32("unk_dword_02"),
                construct.ULInt32("SizeFile"),
                construct.ULInt32("Offset"),
                construct.ULInt32("unk_dword_03"),
                construct.ULInt32("unk_dword_04"),
                construct.CString("Name", terminators='\x00')
                )

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')

SIG = "BoG_ *90.0&!!  Yy>"
FILENAME = "comm2.exe"

buf = open(FILENAME, "rb").read()

start = buf.find(SIG, 0)
if start == -1:
    raise Exception("[-] Can't find signature : \"%s\"" % SIG)
s = safeInfo.parse(buf[start:])
print "[+] Safe version detected : %d.%d.%d" % (s['version'], s['subversion'], s['revision'])
e = pe_init.PE(buf)
print hex(e.SHList[-1].offset + e.SHList[-1].rawsize)
off = e.SHList[-1].offset + e.SHList[-1].rawsize
while True:
    file_buf = buf[off: off + 0x120]
    if len(file_buf) != 0x120:
        break
    dfile_buf = ""
    key = off
    for c in file_buf:
        key = ((key * 0x13C6A5) + 0x0D8430DED) & 0xFFFFFFFF
        dfile_buf += chr((ord(c) ^ (key >> 0x18) ^ (key >> 0x10) ^ (key >> 0x08) ^ key) & 0xFF)
    #print hexdump(dfile_buf)
    s = safeEntry.parse(dfile_buf)
    print s
    data_buf = buf[off + s['Offset']:off + s['Offset'] + s['SizeFile']]
    ddata_buf = ""
    # 00C1CF05    69C9 0D661900   IMUL ECX,ECX,19660D                                   ; comm2.0081C419
    # 00C1CF37    81C1 5FF36E3C   ADD ECX,3C6EF35F
    key = off + s['Offset']
    for c in data_buf:
        key = ((key * 0x19660D) + 0x3C6EF35F) & 0xFFFFFFFF
        ddata_buf += chr((ord(c) ^ (key >> 0x18) ^ (key >> 0x10) ^ (key >> 0x08) ^ key) & 0xFF)        
    print hexdump(ddata_buf[:0x40])
    if ddata_buf[0] == '\x4d' and ddata_buf[1] == '\x5a':
        open("res_dir/" + s['Name'], "wb").write(ddata_buf)
    off += s['SizeFile'] + s['Offset']
