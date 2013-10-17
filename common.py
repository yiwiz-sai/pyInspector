#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import glob
import pykd
import pefile
import platform
import win32api
import json

def add_symbolpath(sympath, newdir):
    if sympath.endswith(';'):
        return sympath+newdir
    else:
        return sympath+';'+newdir
    
g_windowsdir=win32api.GetWindowsDirectory()
g_system32dir=os.path.join(g_windowsdir, 'system32')

config=open('config.txt', 'rb').read()
config=json.loads(config)
windbgpath=config.get('windbgpath')
if not os.path.exists(windbgpath):
    raise Exception('%s not exists, modify your config.txt' % windbgpath)
    
pykd.attachKernel()
if not pykd.isKernelDebugging():
    raise Exception("not a kernel debugging")
print 'load symbol, wait....'

g_sympath=config.get('sympath')
if not g_sympath:
    raise Exception('%s can not be null')

print 'your sympath:%s' %   g_sympath
g_sympath=add_symbolpath(g_sympath, g_windowsdir)
g_sympath=add_symbolpath(g_sympath, g_system32dir)
pykd.dbgCommand('.sympath %s' % g_sympath)
pykd.dbgCommand('.reload *')
print 'load symbol ok!'
windbgextdirs=['winxp', 'winext']
default_exts=['kdexts.dll', 'ext.dll', 'exts.dll','kext.dll','kdexts.dll', 'ntsdexts.dll']
for extdirname in windbgextdirs:
    extdirpath=os.path.join(windbgpath, extdirname)
    fl=glob.glob(extdirpath)
    if not fl:
        raise Exception('%s not exists, have you installed the latest windbg?' % extdirpath)
    
    dirpath=fl[0]
    l=os.listdir(dirpath)
    for i in l:
        filepath=os.path.join(dirpath, i)
        if i in default_exts:
            print 'load', filepath
            pykd.dbgCommand('.load %s' % filepath)

print 'load extensions ok'
nt = pykd.module( "nt" )
g_kernelsize=int(nt.size())
g_kernelbase=int(nt.begin())
module_entry=pykd.ptrMWord(pykd.getOffset('nt!PsLoadedModuleList'))
module_entry=pykd.typedVar('nt!_LDR_DATA_TABLE_ENTRY', module_entry)
kernelpath=pykd.loadUnicodeString(module_entry.FullDllName)
name=os.path.basename(kernelpath)
g_kernelpath=os.path.join(g_system32dir, name)
if not os.path.exists(g_kernelpath):
    raise Exception("can't find %s" % g_kernelpath)
imagename=nt.image()
kernelbasepath=os.path.join(g_system32dir, imagename)
import shutil
if not os.path.exists(kernelbasepath):
    shutil.copy(g_kernelpath, kernelbasepath)

g_currentprocess=pykd.typedVar('nt!_EPROCESS', pykd.getCurrentProcess())
print 'current process:%x' % g_currentprocess.getAddress()

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
print
print
print '='*20

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

import win32api
import win32file

def revise_filepath(fullpath=''):
    #fullpath="\\\\??\\\\c:\\tools\\safe\\xu.sys"
    #fullpath='\\SystemRoot\\tools\\safe\\xu.sys'
    #fullpath='\\WINDOWS\\pro \\1e2e.exe'
    #fullpath='\\WINNT\\pro \\1e2e.exe'
    #fullpath='\\device\\harddiskvolume1\\aaaa\\1.exe'
    fullpath=fullpath.lower()
    if fullpath.startswith('\\??\\'):
        fullpath=fullpath[len('\\??\\'):]
        return fullpath
                
    elif fullpath.startswith('\\systemroot\\'):
        fullpath=os.path.join(os.getenv('systemroot'), fullpath[len('\\systemroot\\'):])
        return fullpath
                
    elif fullpath.startswith('%systemroot%\\'):
        fullpath=os.path.join(os.getenv('systemroot'), fullpath[len('%systemroot%\\'):])
        return fullpath
        
    elif fullpath.startswith('\\device\\harddiskvolume'):
        s=win32api.GetLogicalDriveStrings()
        l=s.split('\x00')
        for i in l:
            if i!='':
                name=win32file.QueryDosDevice(i.rstrip('\\')).strip('\x00').lower()
                if fullpath.startswith(name):
                    fullpath=fullpath.replace(name, '')
                    fullpath=os.path.join(i, fullpath)
                    break
        return fullpath
        
    elif fullpath.startswith('\\windows\\'):
        windowsdir=win32api.GetWindowsDirectory()
        fullpath=os.path.join(windowsdir, fullpath[len('\\windows\\'):])
        return fullpath
        
    elif fullpath.startswith('\\winnt\\'):
        windowsdir=win32api.GetWindowsDirectory()
        fullpath=os.path.join(windowsdir, fullpath[len('\\winnt\\'):])
        return fullpath
    
    elif fullpath.startswith('\\'):
        s=win32api.GetLogicalDriveStrings()
        l=s.split('\x00')
        for i in l:
            if i!='':
                drivername=i.rstrip('\\')
                newfullpath=os.path.join(drivername, fullpath)
                if os.path.exists(newfullpath):
                    return newfullpath
        return fullpath
    else:
        return fullpath

def guess_filepath(filepath, name=''):
    try:
        if filepath:
            if os.path.exists(filepath):
                name=os.path.basename(filepath)
            else:
                for i in ['system32', 'system32\\drivers']:
                    windowsdir=win32api.GetWindowsDirectory()
                    newfilepath=os.path.join(windowsdir, i,  filepath)
                    if os.path.exists(newfilepath):
                        filepath=newfilepath
                        name=os.path.basename(filepath)
                        break
                    elif name:
                        newfilepath=os.path.join(windowsdir, i,  name)
                        if os.path.exists(newfilepath):
                            filepath=newfilepath
                            break
        elif name:
            windowsdir=win32api.GetWindowsDirectory()
            newfilepath=os.path.join(g_system32dir,  name)
            if os.path.exists(newfilepath):
                filepath=newfilepath

    except Exception, err:
        print traceback.format_exc()
        
    return (filepath.lower(), name.lower())

if __name__=='__main__':
    pass
