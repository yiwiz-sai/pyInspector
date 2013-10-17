#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *
mmhighestuseraddress=pykd.ptrPtr(pykd.getOffset('nt!MmHighestUserAddress'))
class ProcessInfo(object):
    def init(self, eprocessobj):
        try:
            if eprocessobj.ObjectTable<mmhighestuseraddress or eprocessobj.VadRoot<mmhighestuseraddress or eprocessobj.QuotaBlock<mmhighestuseraddress:
                return False
        
            self.eprocessaddr=int(eprocessobj)
            self.pid=int(eprocessobj.UniqueProcessId)
            self.parentpid=int(eprocessobj.InheritedFromUniqueProcessId)
            self.peb=int(eprocessobj.Peb)
            filepath=pykd.loadUnicodeString(eprocessobj.SeAuditProcessCreationInfo.ImageFileName.Name)
            filepath=revise_filepath(filepath)
            name=pykd.loadChars(eprocessobj.ImageFileName, 16)
            if name.startswith('\x00'):
                name=''
            name=name.strip('\x00')
            self.filepath, self.name=guess_filepath(filepath, name)
            return True
            
        except Exception, err:
            print traceback.format_exc()
            return False
        
def listProcessByPspcidTable():
    processlist=[]
    try:
        cmdline='!process 0 0'
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        for i in r:
            if i.startswith('PROCESS '):
                startpos=len('PROCESS ')
                endpos=i.find(' ', startpos)
                eprocessaddr=int(i[startpos:endpos], 16)
                eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
                info=ProcessInfo()
                if info.init(eprocessobj):
                    processlist.append(info)

    except Exception, err:
        print traceback.format_exc()
    return processlist

def listProcessBySessionProcessLinks(sourceprocesslist=[]):
    processlist={}
    try:
        if not sourceprocesslist:
            sourceprocesslist=listProcessByPsActiveProcessHead()
        
        SessionProcessLinks_table=[]
        for eproc in sourceprocesslist:
            eprocessaddr=eproc.eprocessaddr
            if eprocessaddr not in processlist:
                #print hex(eprocessaddr)
                eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
                SessionProcessLinks=eprocessobj.SessionProcessLinks
                SessionProcessLinks=int(SessionProcessLinks)
                if SessionProcessLinks and SessionProcessLinks not in SessionProcessLinks_table:
                    SessionProcessLinks_table.append(SessionProcessLinks)
                    l=pykd.typedVarList(SessionProcessLinks, 'nt!_EPROCESS', 'SessionProcessLinks')
                    for i in l:
                        if int(i) not in processlist:
                            info=ProcessInfo()
                            if info.init(i):
                                processlist[int(i)]=info

    except Exception, err:
        print traceback.format_exc()
    return processlist.values()
    
def listProcessByWorkingSetExpansionLinks(sourceprocesslist=[]):
    processlist={}
    try:
        if not sourceprocesslist:
            sourceprocesslist=listProcessByPsActiveProcessHead()
        
        WorkingSetExpansionLinks_list=[]
        for eproc in sourceprocesslist:
            eprocessaddr=eproc.eprocessaddr
            if eprocessaddr not in processlist:
                #print hex(eprocessaddr)
                eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
                WorkingSetExpansionLinks=eprocessobj.Vm.WorkingSetExpansionLinks
                WorkingSetExpansionLinks=int(WorkingSetExpansionLinks)
                if WorkingSetExpansionLinks and WorkingSetExpansionLinks not in WorkingSetExpansionLinks_list:
                    WorkingSetExpansionLinks_list.append(WorkingSetExpansionLinks)
                    l=pykd.typedVarList(WorkingSetExpansionLinks, 'nt!_EPROCESS', 'Vm.WorkingSetExpansionLinks')
                    for i in l:
                        if int(i) not in processlist:
                            info=ProcessInfo()
                            if info.init(i):
                                processlist[int(i)]=info

    except Exception, err:
        print traceback.format_exc()
    return processlist.values()
    
def listProcessByPsActiveProcessHead():
    processlist=[]
    try:
        PsActiveProcessHead=pykd.getOffset('nt!PsActiveProcessHead')
        l=pykd.typedVarList(PsActiveProcessHead, 'nt!_EPROCESS', 'ActiveProcessLinks')
        for i in l:
            info=ProcessInfo()
            if info.init(i):
                processlist.append(info)
            
    except Exception, err:
        print traceback.format_exc()
    return processlist


def findProcessObject(name):
    name=name.lower()
    l=listProcessByPsActiveProcessHead()
    for i in l:
        if i.name==name:
            return i
    return None

import win32process
import copy

def inspectHiddenProcess():
    try:
        pidlist=list(win32process.EnumProcesses())
        funclist=\
        [
            listProcessByPsActiveProcessHead, 
            listProcessBySessionProcessLinks, 
            listProcessByWorkingSetExpansionLinks, 
            listProcessByPspcidTable, 
        ]
        print 'eprocess pid ppid peb name filepath'
        for func in funclist:
            print '-'*10,'find hidden process by %s' % func.func_name,'-'*10
            processlist=func()
            #print len(processlist)
            pidlist2=copy.deepcopy(pidlist) 
            for i in processlist:
                if i.pid not in pidlist2:
                    print '%x %5d %5d %x %s %s' % (i.eprocessaddr, i.pid, i.parentpid, i.peb, i.name, i.filepath)
                else:
                    pidlist2.remove(i.pid)
            for i in pidlist2:
                print "pid %d can't be found by %s" % (i, func.func_name)
        print 
        print 'inspect completely'
    except Exception, err:
        print traceback.format_exc()
def help():
    print '-inspect'
    print '-list0 eprocessaddr #listProcessByPsActiveProcessHead'
    print '-list1 eprocessaddr #listProcessBySessionProcessLinks'
    print '-list2 eprocessaddr #listProcessByWorkingSetExpansionLinks'
    print '-list3 eprocessaddr #listProcessByPspcidTable'
    

if __name__=='__main__':
    try:
        if len(sys.argv)<2:
            help()
            sys.exit(0)
            
        if sys.argv[1]=='-inspect':
            inspectHiddenProcess()
        elif sys.argv[1]=='-list0':
            processlist=listProcessByPsActiveProcessHead()
            for i in processlist:
                print '%x %5d %5d %x %s %s' % (i.eprocessaddr, i.pid, i.parentpid, i.peb, i.name, i.filepath)
                
        elif sys.argv[1]=='-list1':
            processlist=listProcessBySessionProcessLinks()
            for i in processlist:
                print '%x %5d %5d %x %s %s' % (i.eprocessaddr, i.pid, i.parentpid, i.peb, i.name, i.filepath)
                
        elif sys.argv[1]=='-list2':
            processlist=listProcessByWorkingSetExpansionLinks()
            for i in processlist:
                print '%x %5d %5d %x %s %s' % (i.eprocessaddr, i.pid, i.parentpid, i.peb, i.name, i.filepath)
                
        elif sys.argv[1]=='-list3':
            processlist=listProcessByPspcidTable()
            for i in processlist:
                print '%x %5d %5d %x %s %s' % (i.eprocessaddr, i.pid, i.parentpid, i.peb, i.name, i.filepath)
                
        else:
            help()
    except Exception, err:
        print traceback.format_exc()
        

