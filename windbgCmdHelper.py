#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
import glob


def init():
    pykd.attachKernel()
    if not pykd.isKernelDebugging():
        raise Exception("not a kernel debugging")
    print 'load symbol, wait....'
    pykd.dbgCommand('.reload /f nt')
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

def dd(cmdline):
    r=pykd.dbgCommand(cmdline)
    r=r.splitlines()
    startaddr=int(r[0].split(' ')[0], 16)
    l=[]
    for i in r:
        i=i.split(' ')[1:]
        for j in i:
            if j:
                l.append(int(j, 16))
                
    return [startaddr, l]
    
def dds(cmdline):
    r=pykd.dbgCommand(cmdline)
    r=r.splitlines()
    l=[]
    for i in r:
        i=i.split(' ')
        addr=int(i[0], 16)
        data=int(i[2], 16)
        if len(i)>=4:
            symbolname=i[3]
        else:
            symbolname=''
        l.append([addr, data, symbolname])
    return l
    
def ln(cmdline):
    r=pykd.dbgCommand(cmdline)
    return r.split('|')

def get_unicode_string(s):
    pos=s.find('_UNICODE_STRING ')
    s=s[pos+len('_UNICODE_STRING'):].strip().strip('"')
    return s
    
def getkernelinfo():
    nt = pykd.module( "nt" )
    kernelsize=int(nt.size())
    kernelpath=nt.image()
    
    r=dd('dd nt L1')
    kernelbase=r[0]
    if not os.path.exists(kernelpath):
        systemdir="c:\\windows\\system32\\"
        if not os.path.exists(systemdir):
            systemdir="c:\\winnt\\system32\\"
            if not os.path.exists(systemdir):
                raise Exception("can't find system dir")
                
        PsLoadedModuleList=dd('dd nt!PsLoadedModuleList L1')[1][0]
        cmdline="dt _ldr_data_table_entry %x -b FullDllName" % PsLoadedModuleList
        r=pykd.dbgCommand(cmdline)
        name=get_unicode_string(r)
        name=os.path.basename(name)
        kernelpath=systemdir+name
        if not os.path.exists(systemdir):
            raise Exception("can't find kernel path")
    
    return (kernelbase, kernelpath, kernelsize)

def getcpunumber():
    r=pykd.dbgCommand('!cpuid')
    r=r.splitlines()
    start=0
    cpunum=0    
    for i in r:
        i=i.strip()
        if start==0:
            if i.find('Manufacturer')!=-1:
                start=1
        else:
            if i=='':
                continue
            cpunum+=1
        
    return cpunum

init()
g_kernelbase, g_kernelpath, g_kernelsize=getkernelinfo()
g_cpunumber=getcpunumber()
print 'kernel:%s base:%x size:%x(%d)' % (g_kernelpath, g_kernelbase, g_kernelsize, g_kernelsize)
print 'cpunumber:', g_cpunumber
if __name__=='__main__':
    pass
