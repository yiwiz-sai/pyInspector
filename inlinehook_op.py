#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pefile
import pykd
from common import *

def repairInlineHook(modulepath, startaddr, endaddr, eprocessaddr=None):
    try:
        symbolpath=g_sympath+';'+os.path.abspath(os.path.dirname(modulepath))
        if eprocessaddr:
            cmdline='.process /P %x;.sympath %s;' % (eprocessaddr, symbolpath)
            r=pykd.dbgCommand(cmdline)
        cmdline='.reload;'
        r=pykd.dbgCommand(cmdline)
        
        if modulepath==g_kernelpath:
            cmdline='!chkimg nt -r %x %x -v -d -f' % (startaddr, endaddr)
        else:
            cmdline='!chkimg %s -r %x %x -v -d -f' % (os.path.basename(modulepath), startaddr, endaddr)
        
        r=pykd.dbgCommand(cmdline)
        for i in r:
            print i
    except Exception, err:
        print traceback.format_exc()
        
def checkInlineHook(modulepath=g_kernelpath, baseaddr=g_kernelbase, eprocessaddr=None):
    try:
        print 'scan inlinehook in %s' % modulepath
        symbolpath=g_sympath+';'+os.path.abspath(os.path.dirname(modulepath))
        if eprocessaddr:
            cmdline='.process /P %x;.sympath %s;' % (eprocessaddr, symbolpath)
            r=pykd.dbgCommand(cmdline)
        cmdline='.reload;'
        r=pykd.dbgCommand(cmdline)
        filedata=open(modulepath, 'rb').read()
        pe = pefile.PE(data=filedata, fast_load=True)
        if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
            raise Exception("%s is not a pe file" % modulepath)
        for i in pe.sections:
            try:
                if pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_DISCARDABLE']&i.Characteristics:
                    #print i.Name, 'discard'
                    continue
                elif not (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']&i.Characteristics):
                    #print i.Name, 'not executable'
                    continue
                
                comparesize=i.Misc_VirtualSize
                fileoffsetstart=i.PointerToRawData
                fileoffsetend=fileoffsetstart+comparesize
                memoffsetstart=baseaddr+ i.VirtualAddress
                memoffsetend=memoffsetstart+comparesize
                print '-'*20
                print '%s :%x %x <--> %x %x  size:%d' % (i.Name, fileoffsetstart, fileoffsetend, memoffsetstart, memoffsetend, comparesize)
                if modulepath==g_kernelpath:
                    cmdline='!chkimg nt -r %x %x -v -d' % (memoffsetstart, memoffsetend)
                else:
                    cmdline='!chkimg %s -r %x %x -v -d' % (os.path.basename(modulepath), memoffsetstart, memoffsetend)
                
                r=pykd.dbgCommand(cmdline)
                if r.find('0 errors')!=-1:
                    print 'no hooks'
                else:
                    r=r.splitlines()
                    for i in r:
                        print i
                    
            except Exception, err:
                print traceback.format_exc()
     
    except Exception, err:
        print traceback.format_exc()
    
if __name__=='__main__':
    checkInlineHook(modulepath=r'C:\tools\pyInspector\calc1234567890123456.exe', baseaddr=0x01000000, eprocess=0x85f4e760)
    pass

