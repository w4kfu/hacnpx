import struct
from ctypes import *
import construct
from elfesteem import *
from capstone import *

SteamPacker_sig2 = construct.Struct("SteamPacker_sig2",
                    construct.ULInt32("unk_dword_00"),
                    construct.ULInt32("unk_dword_01"),
                    construct.ULInt32("unk_dword_02"),
                    construct.ULInt32("unk_dword_03"),
                    construct.ULInt32("unk_dword_04"),
                    construct.ULInt32("VA_BIND"),
                    construct.ULInt32("RVA_ACTUAL_STRUCT"),
                    construct.ULInt32("XOR_KEY"),
                    construct.ULInt32("Offset"),
                    construct.ULInt32("Size"),
                    construct.ULInt32("unk_dword_10"),
                    construct.ULInt32("unk_dword_11"),
                    construct.ULInt32("unk_dword_12"),
                    construct.ULInt32("unk_dword_13"),
                    construct.ULInt32("VA_DLL_OFFSET"),
                    construct.ULInt32("SIZE_DLL_OFFSET"),
                    construct.ULInt32("XTEA_KEY_OFFSET"),
                    #construct.Array(0x20, construct.ULInt8("AES_KEY")),
                    #construct.Array(0x10, construct.ULInt8("AES_IV")),
                    #construct.Array(0x10, construct.ULInt8("BUF_PAD")),
                    #construct.Array(0x4, construct.ULInt32("XTEA_KEY")),
                    #construct.ULInt32("unk_dword_17"),
                    #construct.ULInt32("unk_dword_18"),
                    #construct.ULInt32("unk_dword_19"),
                    #construct.ULInt32("unk_dword_20"),
                    #construct.ULInt32("unk_dword_21"),
                    #construct.ULInt32("unk_dword_22"),
                    #construct.ULInt32("GetModuleHandleA_idata"),
                    #construct.ULInt32("GetModuleHandleW_idata"),
                    #construct.ULInt32("LoadLibraryA_idata"),
                    #construct.ULInt32("LoadLibraryW_idata"),
                    #construct.ULInt32("GetProcAddress_idata"),
                    #construct.ULInt32("unk_dword_27"),
                    #construct.ULInt32("unk_dword_28"),
                    #construct.ULInt32("unk_dword_29"),
                               )

SteamPacker_sig3 = construct.Struct("SteamPacker_sig3",
                    construct.ULInt32("unk_dword_00"),
                    construct.ULInt32("unk_dword_01"),
                    construct.ULInt32("GetProcAddress_idata"),
                    construct.ULInt32("LoadLibraryA_idata"),
                    construct.ULInt32("unk_dword_04"),
                    construct.ULInt32("FLAG"),
                    construct.ULInt32("unk_dword_06"),
                    construct.ULInt32("BindBaseAddress"),
                    construct.ULInt32("unk_dword_08"),
                    construct.ULInt32("unk_dword_09"),
                    construct.ULInt32("OriginalEntryPoint"),
                    construct.ULInt32("TextBaseAddress"),
                    construct.ULInt32("TestRawSize"),
                    construct.ULInt32("XorInitKey"),
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

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')

def decipher(v, k):
    y=c_uint32(v[0])
    z=c_uint32(v[1])
    sum=c_uint32(0xC6EF3720)
    delta=0x9E3779B9
    n=32
    w=[0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1

    w[0]=y.value
    w[1]=z.value
    return w

def GetDword(buf, endian="<"):
    dword = struct.unpack(endian + "I", buf[:4])[0]
    return (dword, buf[4:])

def unxor(buf, key=0):
    res_buf = ""
    if key == 0:
        key, buf = GetDword(buf)
    for i in xrange(0, len(buf) / 4):
        val, buf = GetDword(buf)
        res_buf += struct.pack("<I", key ^ val)
        key = val
    return res_buf
        
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

from capstone.x86 import *

def handle_sig_2(e, filename):
    buf = e.drva[e.Opthdr.AddressOfEntryPoint + 0x0E:e.Opthdr.AddressOfEntryPoint + 0x20]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    dis = list(md.disasm(buf, e.NThdr.ImageBase + e.Opthdr.AddressOfEntryPoint + 0x0E))
    if dis[0].operands[1].type == X86_OP_IMM:
        print "[+] VA STRUCT : 0x%08X" % dis[0].operands[1].value.imm
        va_struct = dis[0].operands[1].value.imm
    else:
        print "[-] NOT AN IMMEDIATE WTF!"
        return
    buf = e.drva[va_struct - e.NThdr.ImageBase:va_struct - e.NThdr.ImageBase + (0xDD * 4)]
    buf = unxor(buf)
    sp = SteamPacker_sig2.parse(buf)
    print_info_sig(sp)
    #print "0x%x: %15s \t%s\t%s" % (i.address, ' '.join("%02X" % x for x in i.bytes), i.mnemonic, i.op_str)
    #if b[0] == "\xC7":  # mov dword ptr
        #pass
    #elif b[0] == "\xBE":    # mov esi, XXX
        #pass
    #else:
        #print "[-] PATTERN NOT DETECT!"
        #return

def handle_sig_3(e, filename):
    buf = e.drva[e.Opthdr.AddressOfEntryPoint + 0x0E:e.Opthdr.AddressOfEntryPoint + 0x20]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    dis = list(md.disasm(buf, e.NThdr.ImageBase + e.Opthdr.AddressOfEntryPoint + 0x0E))
    if dis[0].operands[1].type == X86_OP_IMM:
        print "[+] VA STRUCT : 0x%08X" % dis[0].operands[1].value.imm
        va_struct = dis[0].operands[1].value.imm
    else:
        print "[-] NOT AN IMMEDIATE WTF!"
        return
    buf = e.drva[va_struct - e.NThdr.ImageBase:va_struct - e.NThdr.ImageBase + (0xDD * 4)]
    buf = unxor(buf)
    print hexdump(buf)
    sp = SteamPacker_sig3.parse(buf)
    print_info_sig(sp)
    if sp['FLAG'] & 0x10 != 0:
        print "[+] DuplicanteHandle And CRC"
    elif sp['FLAG'] & 0x04 == 0:
        print "[+] Not crypted"
    else:
        print "[+] Crypted"
    return
#VA = 0x021F22F0

OFFSET = 0xBA5AEC
#OFFSET = 0x642C04

#OFFSET_2 = 0xA86000
#OFFSET_3 = 0xA87750

#FILE_NAME = "Dungeon Siege III.exe"
#FILE_NAME = "BF2.exe"
FILE_NAME = "Bioshock.exe"
#FILE_NAME = "CitiesXL_2011.exe"
#FILE_NAME = "RCT3plus.exe"

e = pe_init.PE(open(FILE_NAME, 'rb').read())
#handle_sig_2(e, FILE_NAME)
handle_sig_3(e, FILE_NAME)
sys.exit()

fd_in = open(FILE_NAME, "rb")
fd_in.seek(OFFSET, 0)
buf = fd_in.read(0xC2 * 4)
print hexdump(buf)
buf = unxor(buf)
sp = SteamPacker_sig2.parse(buf)
print hexdump(buf)
print_info_sig(sp)

fd_in.close()

e = pe_init.PE(open(FILE_NAME, "rb").read())
print e.NThdr.ImageBase
buf = e.drva[sp['Offset'] - e.NThdr.ImageBase:sp['Offset'] - e.NThdr.ImageBase + sp['Size']]
print hexdump(buf[:0x10])
buf = unxor(buf, sp['XOR_KEY'])
print hexdump(buf)
va_unk_1 = struct.unpack("<I", buf[sp['VA_DLL_OFFSET']:sp['VA_DLL_OFFSET'] + 4])[0]
print "[+] va_unk_1 = 0x%X" % va_unk_1
va_unk_2 = struct.unpack("<I", buf[sp['SIZE_DLL_OFFSET']:sp['SIZE_DLL_OFFSET'] + 4])[0]
print "[+] va_unk_2 = 0x%X" % va_unk_2
#va_unk_3 = struct.unpack("<I", buf[sp['unk_dword_16']:sp['unk_dword_16'] + 4])[0]
#print "[+] va_unk_3 = 0x%X" % va_unk_3
XTEA_KEY = struct.unpack("<LLLL", buf[sp['XTEA_KEY_OFFSET']:sp['XTEA_KEY_OFFSET'] + 0x10])
#va_unk_3 = struct.unpack("<I", buf[sp['unk_dword_15']:sp['unk_dword_15'] + 4])[0]
#print "[+] va_unk_4 = 0x%X" % va_unk_2
dll_buf = e.drva[va_unk_1 - e.NThdr.ImageBase:va_unk_1 - e.NThdr.ImageBase + va_unk_2]
#b = Buffer(dll_buf)
#buf = apply_tea(b, XTEA_KEY)
#print hexdump(buf[:1500])
#fd_out = open("stfu2.dll", "wb")
#fd_out.write(buf)
#fd_out.close()

from Crypto.Cipher import AES

AES_KEY = buf[0x6E4:0x6E4 + 0x20]
BUF_PADDING = buf[0x3AC:0x3AC + 0x20]

print "AES_KEY:"
print hexdump(AES_KEY)
print "BUF_PADDING:"
print hexdump(BUF_PADDING)
AES_IV = BUF_PADDING[:0x10]

obj = AES.new(AES_KEY, AES.MODE_ECB)
AES_IV = obj.decrypt(AES_IV)
print "AES_IV:"
print hexdump(AES_IV)

data = '9980779C609B73576462B221528EF811796DDDA9E1486FB9120F9E5C2EF25468'.decode('hex')

obj = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)

ciphertext = obj.decrypt(data)
print "---"
print hexdump(ciphertext)

sys.exit(0)

sp = SteamPacker.parse(buf)
if sp['signature'] != 0xC0DEC0DE:
    print "[-] signature fail"
size = 0
for a, b in sp.items():
    if type(b) == long or type(b) == int:
        print "+ 0x%04X : %s -> 0x%08X (%d)" % (size, a, b, b)
        size += 4
    elif type(b) == construct.lib.container.ListContainer:
        if type(b[0]) == int:
            print "+ 0x%04X : %s -> %s" % (size, a, ''.join(chr(x) for x in b).encode('hex'))
            size += len(b)
        elif type(b[0]) == long:
            print "+ 0x%04X : %s -> %s" % (size, a, ''.join("0x%08X " % x for x in b))
    else:
        print type(b)

print "----"
print hexdump(buf)
fd_in.seek(OFFSET_2, 0)
buf2 = fd_in.read(0x220)
buf2 = unxor(buf2)
print "----"
print hexdump(buf2)
print buf2


from Crypto.Cipher import AES
import Crypto.Util.Counter
# iv = '7ae0e51c9a3a6a525c80e36a55b186f4'.decode('hex')
# key = '500083025000830200000000000000000070730000707300e0050000000b0000'.decode('hex')

#key = '500083025000830200000000000000000070730000707300e0050000000b0000'.decode('hex')

key = '0085b9e2b1d6563b6ede61aa90fbb2d5d35f0fd14d3139db2195d7174de75ed4'.decode('hex')
#key = '7AE0E51C9A3A6A525C80E36A55B186F428985AE3FE735974B097D67996811F19'.decode('hex')

iv = '7ae0e51c9a3a6a525c80e36a55b186f4'.decode('hex')

obj = AES.new(key, AES.MODE_ECB)
new_iv = obj.decrypt(iv)
print "new_iv:"
print hexdump(new_iv)

iv = '8f14083a756dd85408e6cae8ed37fc7b'.decode('hex')
#iv = '8F14083A756DD85408E6CAE8ED37FC7B'.decode('hex')

#from Crypto.Hash import SHA256
#hash = SHA256.new()
#hash.update(key)
#key = hash.digest()

#ctr = Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))

#print len(key)
obj = AES.new(key, AES.MODE_CBC, iv)

#obj = AES.new(key, AES.MODE_CTR, counter = ctr)
fd_in.seek(0x00000400, 0)
#buf_txt = fd_in.read(0x00736A00)
buf_txt = fd_in.read(0x10)

buf_txt = '28985AE3FE735974B097D67996811F19'.decode('hex') + buf_txt

print "BEFORE:"
print hexdump(buf_txt)

#message = "The answer is no"
ciphertext = obj.decrypt(buf_txt)
print "---"
print hexdump(ciphertext[:0x30])

print "MUST BE:"
print hexdump("558BEC8B550833C93BD174628B421C3B".decode('hex'))

#fd_in.seek(OFFSET_3, 0)
#buf3 = fd_in.read(0x66EC0)
#buf3 = fd_in.read(0x8 * 150)
#buf3 = apply_tea(buf3)
#print hexdump(buf3)
#fd_out = open("stfu.bin", "wb")
#fd_out.write(buf3)
#fd_out.close()



#print hex(VA - 0xD0)
