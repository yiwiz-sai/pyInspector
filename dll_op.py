#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

class ModuleInfo(object):
    def init1(self, ldr):
        try:
            if not int(ldr):
                return False
                
            filepath=revise_filepath(pykd.loadUnicodeString(ldr.FullDllName))
            name=pykd.loadUnicodeString(ldr.BaseDllName)
            self.filepath, self.name=guess_filepath(filepath, name)
            
            self.baseaddr=int(ldr.DllBase)
            self.entrypoint=int(ldr.EntryPoint)
            self.size=int(ldr.SizeOfImage)
            return True
        except Exception, err:
            print traceback.format_exc()
            return False
            
    def init2(self, baseaddr=0, endaddr=0, entrypoint=0, name='', filepath=''):
        try:
            self.baseaddr=int(baseaddr)
            endaddr=int(endaddr)
            
            if endaddr>self.baseaddr:
                self.size=endaddr-self.baseaddr
            else:
                self.size=0
                
            self.entrypoint=int(entrypoint)
            filepath=revise_filepath(filepath)
            self.filepath, self.name=guess_filepath(filepath, name)
            return True
        except Exception, err:
            print traceback.format_exc()
            return False
            
def listModuleByVadRoot(eprocessaddr):
    modulelist=[]
    try:
        cmdline='.process /P %x;.reload;' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        eprocess=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        VadRoot=int(eprocess.VadRoot)
        if not VadRoot:
            return []
        cmdline='!vad %x' % VadRoot
        r=pykd.dbgCommand(cmdline).splitlines()
        for i in r:
            i=i.strip()
            pos=i.find('Exe  EXECUTE_')
            if pos==-1:
                continue

            a=i[pos+len('Exe  '):]
            pos=a.find(' ')
            if pos==-1:
                continue
                    
            type=a[:pos].strip()
            filepath=a[pos+len('  '):].strip()
            
            pos=i.find(')')
            if pos==-1:
                continue
            a=i[pos+1:].lstrip()
            pos=a.find(' ')
            if pos==-1:
                continue
            
            baseaddr=a[:pos].strip()
            baseaddr=int(baseaddr, 16)*0x1000
            
            a=a[pos+1:].lstrip()
            pos=a.find(' ')
            if pos==-1:
                continue
            
            endaddr=a[:pos].strip()
            endaddr=int(endaddr, 16)*0x1000
            info=ModuleInfo()
            if info.init2(baseaddr=baseaddr, endaddr=endaddr, filepath=filepath):
                modulelist.append(info)

    except Exception, err:
        print traceback.format_exc()
    
    return modulelist

def listModuleByLdrList(eprocessaddr):
    modulelist={}
    try:
        cmdline='.process /P %x;.reload;' % eprocessaddr
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
                    if int(ldr) not in modulelist:
                        info=ModuleInfo()
                        if info.init1(ldr):
                            modulelist[int(ldr)]=info
        else:
            print 'peb is 0'
        
    except Exception, err:
        print traceback.format_exc()
        
    return modulelist.values()
    
    
def listModuleByLdrHash(eprocessaddr):
    modulelist={}
    try:
        cmdline='.process /P %x;.reload;' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        try:
            LdrpHashTable=pykd.getOffset('ntdll!LdrpHashTable')
        except:
            print 'get LdrpHashTable symbol fail, maybe ldr is null'
            return []
        if int(LdrpHashTable)!=0:
            for i in xrange(26):
                listhead=LdrpHashTable+i*2*g_mwordsize
                hashlink=listhead
                while 1:
                    hashlink=pykd.ptrPtr(hashlink)
                    if hashlink==listhead:
                        break
                    ldr=pykd.containingRecord(hashlink, 'nt!_LDR_DATA_TABLE_ENTRY', 'HashLinks')
                    if int(ldr) not in modulelist:
                        info=ModuleInfo()
                        if info.init1(ldr):
                            modulelist[int(ldr)]=info

    except Exception, err:
        print traceback.format_exc()
    return modulelist.values()

from process_op import *

def inspectProcessHiddenModule(eprocessaddr=None):
    try:
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
        funclist=\
        [
            listModuleByLdrList, 
            listModuleByLdrHash, 
        ]
        for eprocessinfo in processlist:
            try:
                eprocessaddr=eprocessinfo.eprocessaddr
                print '='*10, 'process:%x pid:%d %s' % (eprocessaddr, eprocessinfo.pid, eprocessinfo.filepath), '='*10
                sourcemodulelist=listModuleByVadRoot(eprocessaddr)
                if not sourcemodulelist:
                    print 'fail to get vad!!!!!'
                    continue
                    
                hooknumber=0
                for func in funclist:
                    modulelist=func(eprocessaddr)
                    #print len(modulelist)
                    modulelist2={}
                    for i in modulelist:
                        modulelist2[i.baseaddr]=i
                    
                    l=[]
                    for i in sourcemodulelist:
                        if i.baseaddr not in modulelist2:
                            l.append(i)
                        else:
                            modulelist2.pop(i.baseaddr)
        
                    if l:
                        print '!'*5, "following modules can not be found by %s" % func.func_name
                        for i in l:
                            print 'base:%x size:%x entry:%x %s %s' % (i.baseaddr, i.size, i.entrypoint, i.name, i.filepath)    
                            hooknumber+=1
                    if modulelist2:
                        print '!'*5, "following modules can be only found by %s" % func.func_name
                        for i in modulelist2.values():
                            print 'base:%x size:%x entry:%x %s %s' % (i.baseaddr, i.size, i.entrypoint, i.name, i.filepath)
                            hooknumber+=1
                
                if hooknumber==0:
                    print 'no hidden dll'
            except Exception, err:
                print traceback.format_exc() 
                    
        print 
        print 'inspect completely'
    except Exception, err:
        print traceback.format_exc() 


def help():
    print '-inspectall'
    print '-inspectone eprocessaddr'
    print '-list0 eprocessaddr #listModuleByVadRoot'
    print '-list1 eprocessaddr #listModuleByLdrList'
    print '-list2 eprocessaddr #listModuleByLdrHash'
    
if __name__=='__main__':
    try:
        if len(sys.argv)<2:
            help()
            sys.exit(0)
            
        if sys.argv[1]=='-inspectall':
            inspectProcessHiddenModule()
        elif sys.argv[1]=='-inspectone':
            eprocessaddr=int(sys.argv[2], 16)
            inspectProcessHiddenModule(eprocessaddr)
            
        elif sys.argv[1]=='-list0':
            eprocessaddr=int(sys.argv[2], 16)
            modulelist=listModuleByVadRoot(eprocessaddr)
            for i in modulelist:
                print 'base:%x size:%x entry:%x %s %s' % (i.baseaddr, i.size, i.entrypoint, i.name, i.filepath)
                
        elif sys.argv[1]=='-list1':
            eprocessaddr=int(sys.argv[2], 16)
            modulelist=listModuleByLdrList(eprocessaddr)
            for i in modulelist:
                print 'base:%x size:%x entry:%x %s %s' % (i.baseaddr, i.size, i.entrypoint, i.name, i.filepath)
                
        elif sys.argv[1]=='-list2':
            eprocessaddr=int(sys.argv[2], 16)
            modulelist=listModuleByLdrHash(eprocessaddr)
            for i in modulelist:
                print 'base:%x size:%x entry:%x %s %s' % (i.baseaddr, i.size, i.entrypoint, i.name, i.filepath)
        else:
            help()
    except Exception, err:
        print traceback.format_exc() 
