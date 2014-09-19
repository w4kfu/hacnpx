from ctypes import *
from ctypes.wintypes import DWORD
import json
from _winreg import *

LocalFree = windll.kernel32.LocalFree
memcpy = cdll.msvcrt.memcpy
CryptProtectData = windll.crypt32.CryptProtectData
CryptUnprotectData = windll.crypt32.CryptUnprotectData

CRYPTPROTECT_UI_FORBIDDEN = 0x01

class DATA_BLOB(Structure):
     _fields_ = [("cbData", DWORD), ("pbData", POINTER(c_char))]

def getData(blobOut):
     cbData = int(blobOut.cbData)
     pbData = blobOut.pbData
     buffer = c_buffer(cbData)
     memcpy(buffer, pbData, cbData)
     LocalFree(pbData);
     return buffer.raw

def Win32CryptProtectData(plainText, entropy):
     bufferIn = c_buffer(plainText, len(plainText))
     blobIn = DATA_BLOB(len(plainText), bufferIn)
     bufferEntropy = c_buffer(entropy, len(entropy))
     blobEntropy = DATA_BLOB(len(entropy), bufferEntropy)
     blobOut = DATA_BLOB()
     if CryptProtectData(byref(blobIn), u"win32crypto.py", byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut)):
         return getData(blobOut)
     else:
         return None

def Win32CryptUnprotectData(cipherText, entropy):
     bufferIn = c_buffer(cipherText, len(cipherText))
     blobIn = DATA_BLOB(len(cipherText), bufferIn)
     bufferEntropy = c_buffer(entropy, len(entropy))
     blobEntropy = DATA_BLOB(len(entropy), bufferEntropy)
     blobOut = DATA_BLOB()
     if CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut)):
         return getData(blobOut)
     else:
         return None

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')


agent_fd = open(".agent.db", "r")
json_agent = agent_fd.read()
agent_fd.close()

dic_agent = json.loads(json_agent)
dic_agent = json.loads(dic_agent['config']['game_data']) # HAX ?
a = dic_agent['platform']['win']['config']['uninstall']
keys = []
for i in a:
    if i.has_key('delete_registry_key') and i['delete_registry_key'].has_key('value'):
        # SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /* AUTORUN ? */
        if 'Run' in i['delete_registry_key']['root']:
            continue
        keys.append((i['delete_registry_key']['root'], i['delete_registry_key']['value']))


aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
for i in keys:
    aKey = OpenKey(aReg, i[0])
    try:
        value, type = QueryValueEx(aKey, i[1])
    except:
        print "[-] Value %s not found!" % i[1]
        continue
    # 3CF943B8  C8 76 F4 AE 4C 95 2E FE  F2 FA 0F 54 19 C0 9C 43
    entropy = "\xC8\x76\xF4\xAE\x4C\x95\x2E\xFE\xF2\xFA\x0F\x54\x19\xC0\x9C\x43"
    r = Win32CryptUnprotectData(value, entropy)
    print "[+] Dump of %s" % i[1]
    print hexdump(r)
