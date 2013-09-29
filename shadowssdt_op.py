#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import binascii
import pefile
import pykd
import windbgCmdHelper


def listShadowSSDT():
    r=windbgCmdHelper.dd('dd win32k L1')
    win32kbase=r[0]
    print 'wink32.sys baseaddr:0x%x' % win32kbase
    
    r=windbgCmdHelper.dd('dd win32k!W32pServiceTable L1')
    W32pServiceTable=r[0]
    print 'win32k!W32pServiceTable:0x%x' % W32pServiceTable
    
    r=windbgCmdHelper.dd('dd win32k!W32pServiceLimit L1')
    W32pServiceLimit=r[1][0]
    print 'win32k!W32pServiceLimit:0x%x(%d)' % (W32pServiceLimit, W32pServiceLimit)
    
    cmdline='dds %x L%x' % (W32pServiceTable, W32pServiceLimit)
    ssdttable=windbgCmdHelper.dds(cmdline)
    
    table_rva=(W32pServiceTable-win32kbase)
    print 'W32pServiceTable rva:0x%x' % table_rva
    
    win32kname='win32k.sys'
    filepath="c:\\windows\\system32\\"+win32kname
    if not os.path.exists(filepath):
        filepath="c:\\winnt\\system32\\"+nt.image()
        if not filepath:
            raise Exception('%s not exists!' % win32kname)

    print 'win32k.sys path:', filepath
    filedata=open(filepath, 'rb').read()
    pe = pefile.PE(data=filedata, fast_load=True)
    if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
        raise Exception("%s is not a pe file" % filepath)

    table_fileoffset=pe.get_offset_from_rva(table_rva)
    print 'W32pServiceTable file offset:0x%x' % table_fileoffset
    if pykd.is64bitSystem():
        itemsize=8
    else:
        itemsize=4
    d=filedata[table_fileoffset:table_fileoffset+itemsize*W32pServiceLimit]
    hooklist=[]
    for i in xrange(W32pServiceLimit):
        source=binascii.b2a_hex(d[i*itemsize:(i+1)*itemsize][::-1])
        source=int(source, 16)-pe.OPTIONAL_HEADER.ImageBase+win32kbase
        addr, current, symbolname=ssdttable[i]
        if source==current:
            print 'source:0x%x current:0x%x %s' % (source, current, symbolname)
        else:
            print 'source:0x%x current:0x%x %s hooked!!!!!!!' % (source, current, symbolname)
            hooklist.append([source, current, symbolname])
    print '='*10+'hook function list'+'='*10
    for i in hooklist:
        print i
        
    print 'hooked function number:', len(hooklist)
    return hooklist

if __name__ == "__main__":
    listShadowSSDT()
