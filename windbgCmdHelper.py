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
    pykd.dbgCommand('.reload *')
    print 'load symbol ok!'
    windbgpath=r'C:\Program Files\Windows Kits\*\Debuggers\x86\winxp'
    fl=glob.glob(windbgpath)
    if not fl:
        raise Exception('%s not exists' % windbgpath)
    
    dirpath=fl[0]
    l=os.listdir(dirpath)
    for i in l:
        filepath=os.path.join(dirpath, i)
        #print filepath
        pykd.dbgCommand('.load %s' % filepath)

init()

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
  
   
if __name__=='__main__':
    pass
