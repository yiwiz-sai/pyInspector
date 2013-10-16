#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import binascii
import pefile
import pykd
from common import *
def inspectShadowSSDT():
    r=pykd.dbgCommand('dd win32k L1').split(' ')
    win32kbase=pykd.addr64(int(r[0],16))
    print 'wink32.sys baseaddr:0x%x' % win32kbase
    
    W32pServiceTable=pykd.getOffset('win32k!W32pServiceTable')
    print 'win32k!W32pServiceTable:0x%x' % W32pServiceTable
        
    W32pServiceLimit=pykd.getOffset('win32k!W32pServiceLimit')
    W32pServiceLimit=pykd.ptrMWord(W32pServiceLimit)
    print 'win32k!W32pServiceLimit:0x%x(%d)' % (W32pServiceLimit, W32pServiceLimit)
    shadowssdttable=pykd.loadPtrs(W32pServiceTable, W32pServiceLimit)
    
    table_rva=(W32pServiceTable-win32kbase)
    print 'W32pServiceTable rva:0x%x' % table_rva
    
    win32kname='win32k.sys'
    windowsdir=win32api.GetWindowsDirectory()
    filepath=os.path.join(windowsdir, 'system32', win32kname)
    if not os.path.exists(filepath):
        raise Exception('%s not exists!' % win32kname)

    print 'win32k.sys path:', filepath
    filedata=open(filepath, 'rb').read()
    pe = pefile.PE(data=filedata, fast_load=True)
    if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
        raise Exception("%s is not a pe file" % filepath)

    table_fileoffset=pe.get_offset_from_rva(table_rva)
    print 'W32pServiceTable file offset:0x%x' % table_fileoffset
    d=filedata[table_fileoffset:table_fileoffset+g_mwordsize*W32pServiceLimit]
    number=0
    for i in xrange(W32pServiceLimit):
        source=binascii.b2a_hex(d[i*g_mwordsize:(i+1)*g_mwordsize][::-1])
        source=int(source, 16)-pe.OPTIONAL_HEADER.ImageBase+win32kbase
        symbolname=pykd.findSymbol(source)
        current=shadowssdttable[i]
        if source==current:
            print 'source:0x%x current:0x%x %s' % (source, current, symbolname)
        else:
            hooksymbolname=pykd.findSymbol(current)
            print 'source:0x%x %s <-> current:0x%x %s hooked!!!!!!!' % (source, symbolname, current, hooksymbolname)
            number+=1
    print 'hooked function number:', number


if __name__ == "__main__":
    inspectShadowSSDT()
