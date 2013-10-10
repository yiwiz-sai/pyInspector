#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

class ModuleInfo(object):
    def __init__(self, baseaddr=0, size=0, entrypoint=0, name='', dllpath=''):
        self.baseaddr=baseaddr
        self.size=size
        self.entrypoint=entrypoint
        self.dllpath=dllpath
        self.name=name
    
def listModuleByVadRoot(eprocessaddr):
    try:
        eprocess=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        VadRoot=int(eprocess.VadRoot)
        if not VadRoot:
            return
        cmdline='!vad %x' % VadRoot
        r=pykd.dbgCommand(cmdline).splitlines()
        for i in r:
            print i
    except Exception, err:
        print traceback.format_exc()

def listModuleByPeb(eprocessaddr):
    try:
        cmdline='.process /P %x' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        r=pykd.dbgCommand('!peb').splitlines()
        for i in r:
            print i
    except Exception, err:
        print traceback.format_exc()

def add_dll(dll_table, ldr):
    try:
        if int(ldr) in dll_table:
            return
        
        fullpath=pykd.loadUnicodeString(ldr.FullDllName)
        name=pykd.loadUnicodeString(ldr.BaseDllName)
        startaddr=int(ldr.DllBase)
        entrypoint=int(ldr.EntryPoint)
        size=int(ldr.SizeOfImage)
        mo=ModuleInfo(baseaddr=startaddr, size=size, entrypoint=entrypoint, name=name, dllpath=fullpath)
        dll_table[int(ldr)]=mo
    except Exception, err:
        print traceback.format_exc()          
        
def getModuleByLdrList(dll_table, eprocessaddr):
    try:
        cmdline='.process /P %x' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr)
        if int(eprocessobj.Peb)!=0:
            entry=int(eprocessobj.Peb.Ldr.InLoadOrderModuleList)
            entryList1=pykd.typedVarList(entry, 'nt!_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks')
            entry=int(eprocessobj.Peb.Ldr.InMemoryOrderModuleList)
            entryList2=pykd.typedVarList(entry, 'nt!_LDR_DATA_TABLE_ENTRY', 'InMemoryOrderLinks')
            entry=int(eprocessobj.Peb.Ldr.InInitializationOrderModuleList)
            entryList3=pykd.typedVarList(entry, 'nt!_LDR_DATA_TABLE_ENTRY', 'InInitializationOrderLinks')
            for entrylist in [entryList1, entryList2, entryList3]:
                for ldr in entrylist:
                    add_dll(dll_table, ldr)
        else:
            print 'peb is 0, no dlls'
    except Exception, err:
        print traceback.format_exc()

def getModuleByLdrHash(dll_table, eprocessaddr):
    try:
        cmdline='.process /P %x' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        cmdline='.reload;'
        r=pykd.dbgCommand(cmdline)
        
        LdrpHashTable=pykd.getOffset('ntdll!LdrpHashTable')
        if int(LdrpHashTable)!=0:
            for i in xrange(26):
                listhead=LdrpHashTable+i*2*g_mwordsize
                hashlink=listhead
                while 1:
                    hashlink=pykd.ptrPtr(hashlink)
                    if hashlink==listhead:
                        break
                    ldr=pykd.containingRecord(hashlink, 'nt!_LDR_DATA_TABLE_ENTRY', 'HashLinks')
                    add_dll(dll_table, ldr)
        else:
            print 'peb is 0, no dlls'
    except Exception, err:
        print traceback.format_exc()
    
def getModules(eprocessaddr=None):
    dll_table={}
    try:
        if not eprocessaddr:
            PsActiveProcessHead=pykd.getOffset('nt!PsActiveProcessHead')
            entry=pykd.ptrPtr(PsActiveProcessHead)
            eprocessobj=pykd.containingRecord(entry, 'nt!_EPROCESS', 'ActiveProcessLinks')
            eprocessaddr=int(eprocessobj)
        
        getModuleByLdrList(dll_table, eprocessaddr)
        getModuleByLdrHash(dll_table, eprocessaddr)
        
    except Exception, err:
        print traceback.format_exc() 
    
    return dll_table.values()
    
if __name__=='__main__':
    l=getModules(0x893cd020)
    for i in l:
        print '%x %x %x %s %s' % (i.baseaddr, i.size, i.entrypoint, i.name, i.dllpath)
    print 'total numberL:', len(l)
