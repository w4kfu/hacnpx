import construct
import os
import struct
import hashlib
import pylzma
from Crypto.Cipher import Blowfish
import zlib
import logging

SIGNATURE = "AXS.GS.0"

ArchiveAXSGS = construct.Struct("ArchiveAXSGS",
                    construct.String("signature", 8),
                    construct.ULInt32("version"),
                    construct.ULInt32("nb_files"))

AXSString = construct.Struct("AXSString",
                    construct.ULInt32("length"),
                    construct.Bytes("data", lambda ctx: ctx.length))

AXSKeyEntry = construct.Struct("AXSKeyEntry",
                    construct.Array(2, AXSString),
                    construct.ULInt32("unk"))
                               
AXSKeyMan = construct.Struct("AXSKeyMan",
                    construct.ULInt32("nb_entry"),
                    #construct.Array(lambda ctx: ctx.nb_entry, AXSKeyEntry))
                    construct.Array(1, AXSKeyEntry))

binInfo = construct.Struct("binInfo",
            construct.ULInt16("a"),
            construct.ULInt8("b"),
            construct.Value("type", lambda ctx: (ctx["b"] << 16) | ctx["a"]),
            construct.ULInt32("size"),
            construct.ULInt32("unk_dword_00"),
            construct.ULInt8("unk_byte_00"),
            construct.ULInt32("type_compression"),
            construct.ULInt32("length"),
            construct.Bytes("data", lambda ctx: ctx.length))

binInfoNext = construct.Struct("binInfoNext",
            construct.ULInt16("type"),
            construct.ULInt32("size"),
            construct.ULInt32("length"),
            construct.Bytes("data", lambda ctx: ctx.length))

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

def extract_zlib(buf, fname, res_dir):
    o = zlib.decompressobj()
    open(res_dir + fname, "wb").write(o.decompress(buf))

def extract_lzma(buf, fname, res_dir):    
    b = Buffer(buf)
    stream_prop = b.GetByte()
    dico_size = b.GetDword()
    final_length = b.GetQword()
    new_head = struct.pack("<B", stream_prop) + struct.pack("<I", dico_size)
    open(res_dir + fname, "wb").write(pylzma.decompress_compat(new_head + buf[13:]))

def createdir(dirname):
    try:
        os.stat(dirname)
    except:
        os.mkdir(dirname)

class ArchiveAXS:
    def __init__(self, filename):
        self.key = []
        self.bin = []
        self.fname = filename
        self.sig = SIGNATURE
        buf = open(filename, "rb").read()
        start = buf.find(self.sig, 0)
        if start == -1:
            raise Exception("[-] Can't find signature : \"%s\"" % self.sig)
        self.b = Buffer(buf[start:])
        self.sheader = ArchiveAXSGS.parse(self.b.buf)
        self.b.pos += 8 + 4 + 4
        for i in xrange(0, self.sheader['nb_files']):
            unk_dword = self.b.GetDword()
            sec_name = self.b.GetBuffer()
            fname = self.b.GetBuffer()
            size = self.b.GetQword()
            save_pos = self.b.pos
            if sec_name == '.root':
                self.handle_root(fname, size)
            elif sec_name == '.bin':
                self.handle_bin(fname, size)
            else:
                log.warn("section %s not supported" % sec_name)
            self.b.pos = save_pos + size

    def pinfo(self):
        self.sheaderinfo()
        self.scryptinfo()
        self.bininfo()

    def sheaderinfo(self):
        print "[+] Archive version  : 0x%08X (%d)" % (self.sheader['version'], self.sheader['version'])
        print "[+] Archive nb_files : 0x%08X (%d)" % (self.sheader['nb_files'], self.sheader['nb_files'])

    def scryptinfo(self):
        print "[+] Nb key           : 0x%08X (%d)" % (len(self.key), len(self.key))
        for k in self.key:
            print "    Plaintext key    : \"%s\"" % k
            print "    Sha-1            : %s" % hashlib.sha1(k).digest().encode('hex')
            print "    IV               : %s" % Blowfish.new(k, Blowfish.MODE_ECB).encrypt('0000000000000000'.decode('hex')).encode('hex')
            print "---"
            
    def bininfo(self):
        print "[+] Nb binary        : 0x%08X (%d)" % (len(self.bin), len(self.bin))
        for fname, s, type_comp in self.bin:
            print "    FileName         : %s" % fname
            print "    Type             : 0x%08X (%d)" % (s['type'], s['type'])
            if s['type'] & 0x100:
                print "     |-> Blowfish encryption activated"
            if s['type'] & 0x01:
                print "     |-> Compressed with %s" % ("LZMA" if type_comp == 0x01 else "ZLIB")
            else:
                print "     |-> RAW"
            print "---"

    def handle_bin(self, fname, size):
        s1 = binInfo.parse(self.b.buf[self.b.pos:self.b.pos + size])
        self.b.pos += 0x14 + s1['length']
        s2 = binInfoNext.parse(self.b.buf[self.b.pos:self.b.pos + size])
        self.bin.append((fname, s2, s1['type_compression']))

    def handle_root(self, fname, size):
        if fname == '.keyMan':
            s = AXSKeyMan.parse(self.b.buf[self.b.pos:self.b.pos + size])
            # take the first one!
            self.key.append(s['AXSKeyEntry'][0]['AXSString'][1]['data'])
        else:
            log.warn("name %s not supported/interesting" % fname)

    def extract_bin(self):
        if len(self.bin) == 0:
            return
        self.res_dir = self.fname + "_res_dir/"
        createdir(self.res_dir)
        for fname, s, type_comp in self.bin:
            data = s['data']
            if s['type'] & 0x100:
                m = hashlib.sha1()
                m.update(self.key[0])
                key = m.digest()
                iv = Blowfish.new(key, Blowfish.MODE_ECB).encrypt('0000000000000000'.decode('hex'))
                blow = Blowfish.new(key, Blowfish.MODE_CBC, iv)
                if (s['length'] % 0x08) != 0:
                    data = blow.decrypt(s['data'].ljust(len(s['data']) + (8 - (len(s['data']) % 8)), "\x00"))
                else:
                    data = blow.decrypt(s['data'])
            if s['type'] & 0x01:
                if type_comp == 0x01:
                    extract_lzma(data, fname, self.res_dir)
                else:
                    extract_zlib(data, fname, self.res_dir)
            else:
                open(self.res_dir + fname, "wb").write(data)
                    
        

FILENAME = "MaxPayne3.exe"
FILENAME = "LANoire.exe"

log = logging.getLogger("AXSParse")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARN)

archi = ArchiveAXS(FILENAME)
archi.pinfo()
archi.extract_bin()
