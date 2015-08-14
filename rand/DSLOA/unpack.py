from idaapi import *
from idc import *

KEY_1 = 0xD343405F
KEY_2 = 0x3269215F

def getsegmentbase(name):
	segs = Segments()
	for s in segs:
			if SegName(s) == name:
				return SegStart(s)
				
def getsegmentsize(name):
	segs = Segments()
	for s in segs:
			if SegName(s) == name:
				return SegEnd(s) - SegStart(s)

def reverse(x):
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1))
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2))
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4))
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8))
    return ((x >> 16) & 0xFFFF | (x << 16) & 0xFFFF0000)

def xorbyte(ea, v):
	PatchByte(ea, (Byte(ea) ^ v) & 0xFF)
		
def ror(byte, count):
	while count > 0:
		byte = (byte >> 1 | byte << 7) & 0xFF
		count -= 1
	return byte
	
def rorword(x, y):
        x=bin(x & 0xFFFFFFFF)[2:].zfill(16)
        start=x[:-y]
        end=x[-y:]
        return eval('0b'+end+start)
	
def decy1(ea, size, key_1, key_2):
	key_2 = key_2 & 0xFFFF
	for i in xrange(0, size):
		key_2 = (key_2 & 0xFF) | ((key_2 << 8) & 0xFF00)
		key_2 = key_2 - 1
		key_2 = (key_2 & 0xFF00) | (key_2 & 0x0F)
		b = Word(ea + i * 2) ^ key_1
		b = (b + key_2) & 0xFFFF
		b = rorword(b, key_2 & 0xFF)
		b = (b ^ key_2) & 0xFFFF
		PatchWord(ea + i * 2, b)

def decy1b(ea, size, key_1, key_2):		
	key_2 = key_2 & 0xFFFF
	for i in xrange(0, size):
		key_2 = (key_2 & 0xFF) | ((key_2 << 8) & 0xFF00)
		key_2 = key_2 - 1
		key_2 = (key_2 & 0xFF00) | (key_2 & 0x0F)
		b = Byte(ea + i) ^ key_1
		b = (b + ((key_2 >> 8) & 0xFF) & 0xFF)
		b = ror(b, key_2 & 0xFF)
		b = (b ^ key_2) & 0xFF
		key_1 = (key_1 + 1) & 0xFF
		PatchByte(ea + i, b)	
	
def decy2(ea, size):
	for i in xrange(0, size):
		s = Dword(ea + i * 4)
		PatchDword(ea + i * 4, (s >> 16 & 0xFFFF) | ((s & 0xFFFF) << 16))
		
def decy():
	text_start = getsegmentbase(".text")
	text_size =  getsegmentsize(".text")
	reloc_start = getsegmentbase(".reloc")
	reloc_size =  getsegmentsize(".reloc")
	rdata_start = getsegmentbase(".rdata")
	rdata_size =  getsegmentsize(".rdata")	
	print("text_start = %X" % text_start)
	print("text_size = %X" % text_size)
	print("reloc_start = %X" % reloc_start)
	print("reloc_size = %X" % reloc_size)
	print("rdata_start = %X" % rdata_start)
	print("rdata_size = %X" % rdata_size)	
	Magic = reverse(KEY_1 + text_size) ^ Dword(reloc_start + 0x778)
	Magic = Magic ^ reverse(text_size - KEY_1)
	Magic = Magic - text_size
	Magic = (Magic - (Magic & 0xFF)) | ror(Magic & 0xFF, KEY_1 & 0xFF)
	print("MAGIC = %X" % Magic)
	key_1 = reverse(KEY_1) + reverse(rdata_size)
	key_1 = key_1 >> 0x10
	print("key_1 = %X" % key_1)
	start = reloc_start + 0x78C
	print("start = %X" % start)
	decy1(reloc_start + 0x78C, 0x00001B05, key_1, reverse(KEY_1) + reverse(rdata_size))
	decy2(reloc_start + 0x78C, 0x00001B05)
	decy1b(reloc_start + 0x78C, 0x0000360B, rdata_size >> 0x10, rdata_size)
	decy1(reloc_start + 0x78C, 0x00001B05, KEY_1 >> 0x10, KEY_1)
	
def main():
	decy()
	
if __name__ == '__main__':
	main() 