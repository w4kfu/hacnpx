import struct
import shutil
import construct
from elfesteem import *
from Crypto.Cipher import AES

SteamPacker_sig1 = construct.Struct("SteamPacker_sig1",
                    construct.ULInt32("signature"),
                    construct.ULInt32("ImageBase"),
                    construct.ULInt32("unk_dword_01"),
                    construct.ULInt32("AddressOfEntryPoint"),
                    construct.ULInt32("StartSection_Offset"),
                    construct.ULInt32("unk_dword_04"),
                    construct.ULInt32("OriginalEntryPoint"),
                    construct.ULInt32("unk_dword_06"),
                    construct.ULInt32("Size_Payload"),
                    construct.ULInt32("Offset_DLL"),
                    construct.ULInt32("Size_DLL"),
                    construct.ULInt32("unk_dword_10"),
                    construct.ULInt32("FLAG"), # DEBUG : 0x20
                    construct.ULInt32("unk_dword_12"),
                    construct.ULInt32("CRC_DLL"),   # NOT THE WHOLE DLL
                    construct.ULInt32("unk_dword_14"),
                    construct.ULInt32("text_raw_size"),
                    construct.Array(0x20, construct.ULInt8("AES_KEY")),
                    construct.Array(0x10, construct.ULInt8("AES_IV")),
                    construct.Array(0x10, construct.ULInt8("BUF_PAD")),
                    construct.Array(0x4, construct.ULInt32("XTEA_KEY")),
                    construct.ULInt32("unk_dword_16"),
                    construct.ULInt32("unk_dword_17"),
                    construct.ULInt32("unk_dword_18"),
                    construct.ULInt32("unk_dword_19"),
                    construct.ULInt32("unk_dword_20"),
                    construct.ULInt32("unk_dword_21"),
                    construct.ULInt32("GetModuleHandleA_idata"),
                    construct.ULInt32("GetModuleHandleW_idata"),
                    construct.ULInt32("LoadLibraryA_idata"),
                    construct.ULInt32("LoadLibraryW_idata"),
                    construct.ULInt32("GetProcAddress_idata"),
                    construct.ULInt32("unk_dword_27"),
                    construct.ULInt32("unk_dword_28"),
                    construct.ULInt32("unk_dword_29"),
                               )

class Buffer:
    def __init__(self, buf):
        self.buf = buf
        self.length = len(self.buf)
        self.pos = 0

    def GetByte(self):
        byte = struct.unpack("<B", self.buf[self.pos: self.pos + 1])[0]
        self.pos += 1
        return byte

    def GetWord(self, endian = "<"):
        word = struct.unpack(endian + "H", self.buf[self.pos: self.pos + 2])[0]
        self.pos += 2
        return word

    def GetDword(self, endian = "<"):
        dword = struct.unpack(endian + "I", self.buf[self.pos: self.pos + 4])[0]
        self.pos += 4
        return dword

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')

def GetDword(buf, endian="<"):
    dword = struct.unpack(endian + "I", buf[:4])[0]
    return (dword, buf[4:])

def unxor(b, key=0):
    res_buf = ""
    if key == 0:
        key = b.GetDword()
    for i in xrange(0, (b.length - b.pos) / 4):
        val = b.GetDword()
        res_buf += struct.pack("<I", key ^ val)
        key = val
    return (res_buf, key)

def xtea_decrypt(k, v0, v1,n = 32):
    delta, mask = 0x9e3779b9, 0xffffffff
    sum = (delta * n) & mask
    for round in range(n):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
    return (v0, v1)

def apply_tea(b, key):
    res_buf = ""
    k1 = 0x55555555
    k2 = 0x55555555
    for i in xrange(0, b.length / 8):
        v1 = b.GetDword()
        v2 = b.GetDword()
        w = xtea_decrypt(key, v1, v2, 32)
        res_buf += struct.pack("<I", w[0] ^ k1) + struct.pack("<I", w[1] ^ k2)
        k1 = v1
        k2 = v2
    return res_buf

def print_info_sig(sp):
    size = 0
    for a, b in sp.items():
        if type(b) == long or type(b) == int:
            print "+ 0x%04X : %20s -> 0x%08X (%d)" % (size, a, b, b)
            size += 4
        elif type(b) == construct.lib.container.ListContainer:
            #if type(b[0]) == int:
            if a != "XTEA_KEY":
                print "+ 0x%04X : %20s -> %s" % (size, a, ''.join(chr(x) for x in b).encode('hex'))
                size += len(b)
            #elif type(b[0]) == long:
            else:
                print "+ 0x%04X : %20s -> %s" % (size, a, ''.join("0x%08X " % x for x in b))
        else:
            print type(b)

def handle_sig(fname, e):
    b = Buffer(e.drva[e.Opthdr.AddressOfEntryPoint - 0xD0:e.Opthdr.AddressOfEntryPoint])
    buf, key = unxor(b)
    sp = SteamPacker_sig1.parse(buf)
    if sp['signature'] != 0xC0DEC0DE:
        print "[-] signature 0xC0DEC0DE fail"
        return
    
    #print_info_sig(sp)
    
    offset_stage = e.Opthdr.AddressOfEntryPoint - sp['StartSection_Offset']
    size_stage = (sp['Size_Payload'] + 0xF) & 0xFFFFFFF0
    b = Buffer(e.drva[offset_stage:(offset_stage + size_stage)])
    (buf_stage, key) = unxor(b, key)
    
    #print hexdump(buf_stage)
    
    dll_stage = e.Opthdr.AddressOfEntryPoint - sp['StartSection_Offset'] + sp['Offset_DLL']
    b = Buffer(e.drva[dll_stage:(dll_stage + sp['Size_DLL'])])
    buf_dll = apply_tea(b, sp['XTEA_KEY'])
    open("steamdrmp.dll", "wb").write(buf_dll)
    obj = AES.new(''.join(chr(x) for x in sp['AES_KEY']), AES.MODE_ECB)
    new_iv = obj.decrypt(''.join(chr(x) for x in sp['AES_IV']))
    obj = AES.new(''.join(chr(x) for x in sp['AES_KEY']), AES.MODE_CBC, new_iv)
    addr, size = 0, 0
    for section in e.SHList:
        if (".text" in section.name):
            offset = section.offset
            addr = section.addr
            size = section.size
    if addr == 0 or size == 0:
        print "[-] can't find .text"
    buf = e.drva[addr:addr + size]
    buf = ''.join(chr(x) for x in sp['BUF_PAD']) + buf
    if (len(buf) % 16) != 0:
        buf = buf.ljust(len(buf) + (16 - (len(buf) % 16)), "\x00")
    buf = obj.decrypt(buf)
    shutil.copyfile(fname, fname + "_un.exe")
    fd = open(fname + "_un.exe", "rb+")
    fd.seek(offset, 0)
    fd.write(buf)
    fd.close()
    print "[+] OEP    : 0x%X" % sp['AddressOfEntryPoint']
    print "[+] VA_OEP : 0x%X" % (sp['AddressOfEntryPoint'] + sp['ImageBase'])
    return

FILENAME = "South Park - The Stick of Truth.exe"

e = pe_init.PE(open(FILENAME, 'rb').read())
handle_sig(FILENAME, e)
