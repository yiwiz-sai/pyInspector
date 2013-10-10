#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pefile
import pykd
from common import *

def listIATTable(eprocessaddr, loadmodules={}):
    try:
        if eprocess:
            cmdline='.process /P %x;.sympath %s;' % (eprocess, symbolpath)
            r=pykd.dbgCommand(cmdline)
        
        filedata=open(modulepath, 'rb').read()
        pe = pefile.PE(data=filedata, fast_load=True)
        if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
            raise Exception("%s is not a pe file" % modulepath)
        pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'])
        for i in pe.DIRECTORY_ENTRY_IMPORT:
            print '-'*10+i.dll+'-'*10
            #if i.dll not in loadmodules:
            #    loadmodules[i.dll]=
            for j in i.imports:
                print j.ordinal, j.name
                
            cmdline=''
    except Exception, err:
        print err
        
if __name__=='__main__':
    checkIATTable('c:\\WINDOWS\\system32\\wsock32.dll')
    pass

'''    
try:
    memdata=''
    cmdline='db %x %x' % (memoffsetstart, memoffsetend-1)
    r=pykd.dbgCommand(cmdline)
    r=r.splitlines()
    for i in r:
        r=i.strip().split('  ')[1].split(' ')
        for j in r:
            for a in j.split('-'):
                memdata+=a
    #memdata=binascii.a2b_hex(memdata)
    rawdata=filedata[fileoffsetstart:fileoffsetend]
    print binascii.b2a_hex(rawdata)[0:10]
    print memdata[0:10]
    #if memdata!=rawdata:
    #    print 'fuck'
    #else:
     #   print 'ok'
    #print len(memdata), len(memdata2), len(rawdata)
except Exception, err:
    print err'''
