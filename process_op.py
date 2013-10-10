#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

class ProcessInfo(object):
    def __init__(self, eprocess=None):
        super(ProcessInfo, self).__init__()
        self.eprocess=int(eprocess)
        self.pid=int(eprocess.UniqueProcessId)
        self.parentpid=int(eprocess.InheritedFromUniqueProcessId)
        self.name=pykd.loadChars(eprocess.ImageFileName,16)
        self.peb=int(eprocess.Peb)
        self.fullpath=pykd.loadUnicodeString(eprocess.SeAuditProcessCreationInfo.ImageFileName.Name)
        
mmhighestuseraddress=pykd.getOffset('nt!MmHighestUserAddress')
def add_process(eprocess_table, eprocessobj):
    try:
        eprocessaddr=int(eprocessobj)
        if eprocessaddr in eprocess_table:
            return
        if eprocessobj.ObjectTable<mmhighestuseraddress or eprocessobj.VadRoot<mmhighestuseraddress or eprocessobj.QuotaBlock<mmhighestuseraddress:
            #print 'invalid process:', hex(eprocessobj), 'pid:', int(eprocessobj.UniqueProcessId)
            eprocess_table[eprocessaddr]=None
        else:
            #print hex(eprocessobj)
            eprocess_table[eprocessaddr]=ProcessInfo(eprocessobj)
    except Exception, err:
        pass
        
def add_process2(eprocess_table, eprocessaddr):
    try:
        eprocessaddr=pykd.addr64(eprocessaddr)
        if eprocessaddr in eprocess_table:
            return
    
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        if eprocessobj.ObjectTable<mmhighestuseraddress or eprocessobj.VadRoot<mmhighestuseraddress or eprocessobj.QuotaBlock<mmhighestuseraddress:
            #print 'invalid process:', hex(eprocessobj), 'pid:', int(eprocessobj.UniqueProcessId)
            eprocess_table[eprocessaddr]=None
        else:
            #print hex(eprocessobj)
            eprocess_table[eprocessaddr]=ProcessInfo(eprocessobj)    
    except Exception, err:
        pass

def listProcessByPspcidTable(eprocess_table={}):
    try:
        cmdline='!process 0 0'
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        for i in r:
            if i.startswith('PROCESS '):
                startpos=len('PROCESS ')
                endpos=i.find(' ', startpos)
                eprocessaddr=int(i[startpos:endpos], 16)
                add_process2(eprocess_table, eprocessaddr)
    except Exception, err:
        print traceback.format_exc()

def listProcessBySessionProcessLinks(eprocess_table={}):
    try:
        if not eprocess_table:
            listProcessByPsActiveProcessHead(eprocess_table)
        
        SessionProcessLinks_table=[]
        for eprocessaddr in eprocess_table.keys():
            if eprocessaddr and eprocess_table[eprocessaddr]:
                #print hex(eprocessaddr)
                eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
                SessionProcessLinks=eprocessobj.SessionProcessLinks
                SessionProcessLinks=int(SessionProcessLinks)
                if SessionProcessLinks and SessionProcessLinks not in SessionProcessLinks_table:
                    SessionProcessLinks_table.append(SessionProcessLinks)
                    processList=pykd.typedVarList(SessionProcessLinks, 'nt!_EPROCESS', 'SessionProcessLinks')
                    for i in processList:
                        add_process(eprocess_table, i)
        return
    except Exception, err:
        print traceback.format_exc()
        
def listProcessByWorkingSetExpansionLinks(eprocess_table={}):
    try:
        if not eprocess_table:
            listProcessByPsActiveProcessHead(eprocess_table)
        
        WorkingSetExpansionLinks_list=[]
        for eprocessaddr in eprocess_table.keys():
            if eprocessaddr and eprocess_table[eprocessaddr]:
                #print hex(eprocessaddr)
                eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
                WorkingSetExpansionLinks=eprocessobj.Vm.WorkingSetExpansionLinks
                WorkingSetExpansionLinks=int(WorkingSetExpansionLinks)
                if WorkingSetExpansionLinks and WorkingSetExpansionLinks not in WorkingSetExpansionLinks_list:
                    WorkingSetExpansionLinks_list.append(WorkingSetExpansionLinks)
                    processList=pykd.typedVarList(WorkingSetExpansionLinks, 'nt!_EPROCESS', 'Vm.WorkingSetExpansionLinks')
                    for i in processList:
                        add_process(eprocess_table, i)
        return 
    except Exception, err:
        print traceback.format_exc()

def listProcessByPsActiveProcessHead(eprocess_table={}):
    try:
        PsActiveProcessHead=pykd.getOffset('nt!PsActiveProcessHead')
        processList=pykd.typedVarList(PsActiveProcessHead, 'nt!_EPROCESS', 'ActiveProcessLinks')
        for i in processList:
            add_process(eprocess_table, i)
    except Exception, err:
        print traceback.format_exc()
          
def listProcess():
    
    eprocess_table={}
    print 'listProcessByPsActiveProcessHead'
    listProcessByPsActiveProcessHead(eprocess_table)
    print 'listProcessBySessionProcessLinks'
    listProcessBySessionProcessLinks(eprocess_table)
    print 'listProcessByWorkingSetExpansionLinks'
    listProcessByWorkingSetExpansionLinks(eprocess_table)
    print 'listProcessByPspcidTable'
    listProcessByPspcidTable(eprocess_table)

    l=filter(lambda x:x!=None, eprocess_table.values())
    l.sort(key=lambda x:x.pid)
    return l
    
if __name__=='__main__':
    starttime=time.time()
    l=listProcess()
    print 'eprocess pid ppid peb name fullpath'
    number=0
    print '='*30
    for i in l:
        print '%x %5d %5d %x %s %s' % (i.eprocess, i.pid, i.parentpid, i.peb, i.name, i.fullpath)
        number+=1
    print 'valid number:', number, 'cost time:', time.time()-starttime
    
    pass
