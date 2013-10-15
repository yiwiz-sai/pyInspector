#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI

import sys, os, time
import binascii
import pefile
import pykd
from common import *

def inspectSSDT():
    kernelbase=g_kernelbase
    KeServiceDescriptorTable=pykd.getOffset('nt!KeServiceDescriptorTable')    
    KiServiceTable=pykd.ptrPtr(KeServiceDescriptorTable)
    serviceCount=pykd.ptrMWord(KeServiceDescriptorTable+2*g_mwordsize)
    print 'nt!KeServiceDescriptorTable:0x%x' % KeServiceDescriptorTable
    print 'nt!KiServiceTable:0x%x' % KiServiceTable
    print 'serviceCount:0x%x(%d)' % (serviceCount, serviceCount)
    ssdttable=pykd.loadPtrs(KiServiceTable, serviceCount)
    
    table_rva=(KiServiceTable-kernelbase)
    print 'KiServiceTable rva:0x%x' % table_rva
    
    filedata=open(g_kernelpath, 'rb').read()
    pe = pefile.PE(data=filedata, fast_load=True)
    if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
        raise Exception("%s is not a pe file" % filepath)

    table_fileoffset=pe.get_offset_from_rva(table_rva)
    print 'KiServiceTable file offset:0x%x' % table_fileoffset
    d=filedata[table_fileoffset:table_fileoffset+g_mwordsize*serviceCount]
    hooklist=[]
    for i in xrange(serviceCount):
        source=binascii.b2a_hex(d[i*g_mwordsize:(i+1)*g_mwordsize][::-1])
        source=pykd.addr64(int(source, 16))-pykd.addr64(pe.OPTIONAL_HEADER.ImageBase)+kernelbase
        symbolname=pykd.findSymbol(source)
        current=ssdttable[i]
        if source==current:
            print 'source:0x%x current:0x%x %s' % (source, current, symbolname)
        else:
            print 'source:0x%x current:0x%x %s hooked!!!!!!!' % (source, current, symbolname)
            hooklist.append([source, current, symbolname])
    print '='*10+'hook function list'+'='*10
    for i in hooklist:
        print i
        
    print 'hooked function number:', len(hooklist)

if __name__ == "__main__":
    inspectSSDT()


