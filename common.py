#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import glob
import pykd
import pefile
import platform

pykd.attachKernel()
if not pykd.isKernelDebugging():
    raise Exception("not a kernel debugging")
print 'load symbol, wait....'
pykd.dbgCommand('.reload *')
print 'load symbol ok!'
windbgextdirs=['winxp', 'winext']
default_exts=['kdexts.dll', 'ext.dll', 'exts.dll','kext.dll','kdexts.dll', 'ntsdexts.dll']
for dirname in windbgextdirs:
    windbgpath=r'C:\Program Files\Windows Kits\*\Debuggers\x86\%s' % dirname
    fl=glob.glob(windbgpath)
    if not fl:
        raise Exception('%s not exists' % windbgpath)
    
    dirpath=fl[0]
    l=os.listdir(dirpath)
    for i in l:
        filepath=os.path.join(dirpath, i)
        if i in default_exts:
            print filepath
            pykd.dbgCommand('.load %s' % filepath)

nt = pykd.module( "nt" )
g_kernelsize=int(nt.size())
g_kernelbase=int(nt.begin())
g_kernelpath=nt.image()
g_kernelchecksum=nt.checksum()
systemdir=os.path.join(os.environ['windir'], 'system32')
g_kernelpath=os.path.join(systemdir, g_kernelpath)
if not os.path.exists(g_kernelpath):
    module_entry=pykd.ptrMWord(pykd.getOffset('nt!PsLoadedModuleList'))
    module_entry=pykd.typedVar('nt!_LDR_DATA_TABLE_ENTRY', module_entry)
    kernelpath=pykd.loadUnicodeString(module_entry.FullDllName)
    name=os.path.basename(kernelpath)
    g_kernelpath=os.path.join(systemdir, name)
    if not os.path.exists(g_kernelpath):
        raise Exception("can't find %s" % g_kernelpath)

g_currentprocess=pykd.typedVar('nt!_EPROCESS', pykd.getCurrentProcess())
print 'current process:%x' % g_currentprocess.getAddress()
g_sympath="srv*%s*http://msdl.microsoft.com/download/symbols" % os.path.join(os.environ['windir'], 'symbolds')
print 'kernel:%s base:%x size:%x(%d)' % (g_kernelpath, g_kernelbase, g_kernelsize, g_kernelsize)

print pykd.getProcessorMode()
g_cpunumber=pykd.ptrMWord(pykd.getOffset('nt!KeNumberProcessors'))
print 'cpunumber:', g_cpunumber
print platform.platform()
g_version=platform.win32_ver()[0]
if pykd.is64bitSystem():
    g_mwordsize=8
else:
    g_mwordsize=4

def is_xp():
    return  g_version=='XP'

def is_vista():
    return  g_version=='VISTA'
    
def is_2008():
    return  g_version=='2008'
    
def is_2003():
    return  g_version=='2003'

def is_2000():
    return  g_version=='2000'

def is_win7():
    return  g_version=='7'
    
def is_win8():
    return  g_version=='8'
    
if __name__=='__main__':
    pass
