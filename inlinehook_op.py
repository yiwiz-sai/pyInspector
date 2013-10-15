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
        
def inspectInlineHook(modulepath=g_kernelpath, baseaddr=g_kernelbase, eprocessaddr=None):
    try:
        print '='*10, 'scan inlinehook in %s' % modulepath, '='*10
        windowsdir=win32api.GetWindowsDirectory()
        system32dir=os.path.join(windowsdir, 'system32')
        driversdir=os.path.join(windowsdir, 'system32', 'drivers')
        symbolpath='%s;%s;%s;%s;' % (g_sympath, system32dir, driversdir,os.path.abspath(os.path.dirname(modulepath)))
        if eprocessaddr:
            cmdline='.process /P %x;.sympath %s' % (eprocessaddr, symbolpath)
            r=pykd.dbgCommand(cmdline)
        else:
            cmdline='.sympath %s' % symbolpath
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
                print '-'*10
                print '%s :%x %x <--> %x %x  size:%d' % (i.Name, fileoffsetstart, fileoffsetend, memoffsetstart, memoffsetend, comparesize)
                if modulepath.lower()==g_kernelpath.lower():
                    cmdline='!chkimg nt -r %x %x -v -d' % (memoffsetstart, memoffsetend)
                else:
                    name=os.path.splitext(os.path.basename(modulepath))[0]
                    cmdline='!chkimg %s -r %x %x -v -d' % (name, memoffsetstart, memoffsetend)
                #print cmdline
                r=pykd.dbgCommand(cmdline)
                if r.find('[')!=-1:
                    print '!!!!hooklist'
                    r=r.splitlines()
                    for i in r:
                        print i
                else:
                    print 'no hooks'
                    
            except Exception, err:
                print traceback.format_exc()
     
    except Exception, err:
        print traceback.format_exc()

from driver_op import *
def inspectAllRing0InlineHook():
    driverlist=listDriverByPsLoadedModuleList()
    for i in driverlist:
        if os.path.exists(i.filepath) and i.baseaddr:
            inspectInlineHook(i.filepath, i.baseaddr)
            print
    
from dll_op import *
def inspectAllRing3InlineHook():
    processlist=listProcessByPsActiveProcessHead()
    for eprocessinfo in processlist:
        print '='*10, 'process:%x pid:%d %s' % (eprocessinfo.eprocessaddr, eprocessinfo.pid, eprocessinfo.filepath), '='*10
        modulelist=listModuleByVadRoot(eprocessinfo.eprocessaddr)
        if not modulelist:
            print 'the process has no modules(vadroot is null)'
        for i in modulelist:
            if os.path.exists(i.filepath) and i.startaddr:
                inspectInlineHook(i.filepath, i.startaddr, eprocessinfo.eprocessaddr)
                print

def inspectProcessInlineHook(eprocessaddr):
    modulelist=listModuleByVadRoot(eprocessaddr)
    if not modulelist:
        print 'the process has no modules(vadroot is null)'
    for i in modulelist:
        if os.path.exists(i.filepath) and i.startaddr:
            inspectInlineHook(i.filepath, i.startaddr, eprocessinfo.eprocessaddr)
            print

def inspectDriverInlineHook(driverobjectaddr):
    info=DriverInfo()
    if info.init1(driverobjectaddr):
        inspectInlineHook(info.filepath, info.baseaddr)

if __name__=='__main__':
    if sys.argv[1]=='allring0':
        inspectAllRing0InlineHook()
    elif sys.argv[1]=='allring3':
        inspectAllRing3InlineHook()
    elif sys.argv[1]=='ring0':
        driverobjectaddr=int(sys.argv[2], 16)
        inspectDriverInlineHook(driverobjectaddr)
    elif sys.argv[1]=='ring3':
        eprocessaddr=int(sys.argv[2], 16)
        inspectProcessInlineHook(eprocessaddr)
    pass

