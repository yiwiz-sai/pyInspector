#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI

import sys, os, time
import binascii
import pefile
import pykd
import windbgCmdHelper

def listSSDT():
    kernelbase=windbgCmdHelper.g_kernelbase
    r=windbgCmdHelper.dd('dd nt!KeServiceDescriptorTable L4')
    KeServiceDescriptorTable=r[0]
    KiServiceTable=r[1][0]
    serviceCount=r[1][2]
    print 'nt!KeServiceDescriptorTable:0x%x' % KeServiceDescriptorTable
    print 'nt!KiServiceTable:0x%x' % KiServiceTable
    print 'serviceCount:0x%x(%d)' % (serviceCount, serviceCount)
    
    cmdline='dds %x L%x' % (KiServiceTable, serviceCount)
    ssdttable=windbgCmdHelper.dds(cmdline)
    table_rva=(KiServiceTable-kernelbase)
    print 'KiServiceTable rva:0x%x' % table_rva
    
    filepath=windbgCmdHelper.g_kernelpath
    filedata=open(filepath, 'rb').read()
    pe = pefile.PE(data=filedata, fast_load=True)
    if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
        raise Exception("%s is not a pe file" % filepath)

    table_fileoffset=pe.get_offset_from_rva(table_rva)
    print 'KiServiceTable file offset:0x%x' % table_fileoffset
    if pykd.is64bitSystem():
        itemsize=8
    else:
        itemsize=4
    d=filedata[table_fileoffset:table_fileoffset+itemsize*serviceCount]
    hooklist=[]
    for i in xrange(serviceCount):
        source=binascii.b2a_hex(d[i*itemsize:(i+1)*itemsize][::-1])
        source=int(source, 16)-pe.OPTIONAL_HEADER.ImageBase+kernelbase
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
    listSSDT()

