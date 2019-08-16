#!/usr/bin/env python

import os
import re
import sys
import struct
import ctypes

from sh4dis import sh4

RED = '\x1B[31m'
NORMAL = '\x1B[0m'
GREEN = '\x1B[32m'

gofer = None
cbuf = None
def disasm_libopcodes(data, addr):
    # initialize disassembler, if necessary
    global gofer, cbuf
    if not gofer:
        gofer = ctypes.CDLL("gofer.so")
        cbuf = ctypes.create_string_buffer(256)
    gofer.get_disasm_libopcodes(addr, data, 4, ctypes.byref(cbuf))
    return cbuf.value.decode('utf-8')

def find_offender(insword):
    with open('./sh4dis/sh4.py') as fp:
        for (i,line) in enumerate(fp.readlines()):
            m = re.search(r'([01dimn]{16})', line)
            if m:
                pattern = m.group(1)
                # mask needs 1's at every {0,1} in pattern, 0's otherwise
                mask = re.sub(r'[01]', r'1', pattern)
                mask = re.sub(r'[^01]', r'0', mask)
                mask = int(mask,2)
                # value preserves all {0,1} in pattern, 0's otherwise
                value = re.sub('[^01]', '0', pattern)
                value = int(value,2)

                if (insword & mask) == value:
                    print("offending line: %d" % (i+1))
                    break

def timedfunc():
    for insword in range(65536):
        data = struct.pack('>H', insword)
        b = disasm(insword, 0x1234)
    print('done')

def differential_disassemble(insword, addr):
    data = struct.pack('>H', insword)

    a = sh4.disasm(insword, addr)
    b = disasm_libopcodes(data, addr)

    b = b.strip()
    b = b.replace('\t', ' ')
    a = a.replace('\t', ' ')

    if a != b and not (a == 'error' and b.startswith('.word ')):
        print(('%08X: %04X -'+RED+a+NORMAL+'-    -'+GREEN+b+NORMAL+'-') % (addr,insword))
        find_offender(insword)
        sys.exit(-1)
    else:
        print(('%08X: %04X -'+GREEN+a+NORMAL+'-    -'+GREEN+b+NORMAL+'-') % (addr,insword))

if __name__ == '__main__':
    mode = None
    if sys.argv[1] in ['time', 'all']:
        mode = sys.argv[1]
    else:
        insword = int(sys.argv[1],16)
        differential_disassemble(insword, 0xFFFFFFFC)    

    if mode == 'time':
        # ~18200 instructions per second
        import timeit
        duration = timeit.timeit('timedfunc()', setup='from __main__ import timedfunc', number=10)
        print('               duration: %f' % duration)
        print('instructions per second: %f' % (65536/duration))

    if mode == 'all':
        for addr in [0xFFFFFFFC, 0x400462, 0x1234, 0x8000]:
            for insword in range(65536):
                differential_disassemble(insword, addr)

            print('verified disassembles at address %08X' % addr)

