#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pefile
import pykd
from common import *

def inspectInlineHook(modulepath, modulebase):
    try:
        print '='*10, 'scan inlinehook in %s' % modulepath, '='*10
        driversdir=os.path.join(g_system32dir, 'drivers')
        symbolpath=g_sympath
        symbolpath=add_symbolpath(symbolpath, driversdir)
        symbolpath=add_symbolpath(symbolpath, os.path.dirname(modulepath))
       
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
                memoffsetstart=modulebase+ i.VirtualAddress
                memoffsetend=memoffsetstart+comparesize
                print '-'*10
                print '%s :%x-%x <--> %x-%x  size:%d' % (i.Name, fileoffsetstart, fileoffsetend, memoffsetstart, memoffsetend, comparesize)
                if modulepath.lower()==g_kernelpath.lower():
                    cmdline='!chkimg nt -r %x %x -v -d' % (memoffsetstart, memoffsetend)
                else:
                    name=os.path.splitext(os.path.basename(modulepath))[0]
                    cmdline='!chkimg %s -r %x %x -v -d' % (name, memoffsetstart, memoffsetend)
                    #repair cmdline='!chkimg %s -r %x %x -v -d -f' % (os.path.basename(modulepath), startaddr, endaddr)
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


from dll_op import *
def inspectProcessInlineHook(eprocessaddr=None):
    if eprocessaddr:
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr)
        eprocessinfo=ProcessInfo()
        if not eprocessinfo.init(eprocessobj):
            print 'it is not a eprocess'
            return
        processlist=[eprocessinfo]   
    else:
        processlist=listProcessByPsActiveProcessHead()
        if not processlist:
            print 'can not get process list'
            return

    for eprocessinfo in processlist:
        print '='*10, 'process:%x pid:%d %s' % (eprocessinfo.eprocessaddr, eprocessinfo.pid, eprocessinfo.filepath), '='*10
        modulelist=listModuleByVadRoot(eprocessinfo.eprocessaddr)
        if not modulelist:
            print 'the process has no modules(vadroot is null)'
            continue
        
        cmdline='.process /P %x' % eprocessinfo.eprocessaddr
        r=pykd.dbgCommand(cmdline)
        for i in modulelist:
            modulepath=i.filepath
            modulebase=i.baseaddr
            if not os.path.exists(modulepath):
                print "can't find file:%s" % modulepath
                continue

            inspectInlineHook(modulepath, modulebase)
            print
            
    print 
    print 'inspect completely'
    
from driver_op import *
def inspectDriverInlineHook(driverobjectaddr=None):
    if driverobjectaddr:
        driverinfo=DriverInfo()
        if not driverinfo.init1(driverobjectaddr):
            print 'fail to get driver info'
            return
        driverlist=[driverinfo]
    else:
        driverlist=listDriverByPsLoadedModuleList()
        if not driverlist:
            print 'can not get driver list'
            return
            
    for i in driverlist:
        modulepath=i.filepath
        modulebase=i.baseaddr
        if not os.path.exists(modulepath):
            print "can't find file:%s" % modulepath
            continue

        inspectInlineHook(modulepath, modulebase)
        print
        
    print 
    print 'inspect completely'


def help():
    print '-inspectallprocess'
    print '-inspectprocess eprocessaddr'
    print '-inspectalldriver'
    print '-inspectdriver driverobjectaddr'
    
if __name__=='__main__':
    try:
        if len(sys.argv)<2:
            help()
            sys.exit(0)
            
        if sys.argv[1]=='-inspectallprocess':
            inspectProcessInlineHook()
                
        elif sys.argv[1]=='-inspectalldriver':
            inspectDriverInlineHook()
    
        elif sys.argv[1]=='-inspectprocess':
            eprocessaddr=int(sys.argv[2], 16)
            inspectProcessInlineHook(eprocessaddr)

        elif sys.argv[1]=='-inspectdriver':
            driverobjectaddr=int(sys.argv[2], 16)
            inspectDriverInlineHook(driverobjectaddr)
            
        else:
            help()
            
    except Exception, err:
        print traceback.format_exc() 
