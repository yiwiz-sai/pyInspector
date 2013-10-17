#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

class ThreadInfo(object):
    def __init__(self, ethreadobj=None):
        super(ThreadInfo, self).__init__()
        self.ethreadaddr=int(ethreadobj)
        self.tid=int(ethreadobj.Cid.UniqueThread)
        self.entrypoint=int(ethreadobj.StartAddress)


def listThreadByTcbThreadListEntry(eprocessaddr):
    threadlist=[]
    try:
        cmdline='.process /P %x;.reload;' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        l=pykd.typedVarList(eprocessobj.Pcb.ThreadListHead, 'nt!_ETHREAD', 'Tcb.ThreadListEntry')
        for i in l:
            info=ThreadInfo(i)
            threadlist.append(info)
    except Exception, err:
        print traceback.format_exc()
    return threadlist

def listThreadByThreadListEntry(eprocessaddr):
    threadlist=[]
    try:
        cmdline='.process /P %x;.reload;' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        l=pykd.typedVarList(eprocessobj.ThreadListHead, 'nt!_ETHREAD', 'ThreadListEntry')
        for i in l:
            info=ThreadInfo(i)
            threadlist.append(info)
    except Exception, err:
        print traceback.format_exc()
    return threadlist


from process_op import *
def inspectProcessHiddenThread(eprocessaddr=None):
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
        
        funclist=[listThreadByTcbThreadListEntry, listThreadByThreadListEntry]
        for eprocessinfo in processlist:
            try:
                eprocessaddr=eprocessinfo.eprocessaddr
                print '='*10, 'process:%x pid:%d %s' % (eprocessaddr, eprocessinfo.pid, eprocessinfo.filepath), '='*10
                
                threadlist={}
                for func in funclist:
                    try:
                        l=func(eprocessaddr)
                    except Exception, err:
                        l=[]
                        print err
                    for info in l:
                        if info.ethreadaddr not in threadlist:
                            threadlist[info.ethreadaddr]=info
                            
                hooknumber=0
                for info in threadlist.values():
                    symbolname=pykd.findSymbol(info.entrypoint)
                    if symbolname.find('!')==-1:
                        print 'ethread:%x tid:%d entry:%x' % (info.ethreadaddr, info.tid, info.entrypoint)
                        hooknumber+=1
                        
                if hooknumber==0:
                    print 'no hidden thread'
                    
            except Exception, err:
                print traceback.format_exc() 
                    
        print 
        print 'inspect completely'
    except Exception, err:
        print traceback.format_exc() 


def help():
    print '-inspectall'
    print '-inspectone eprocessaddr'
    print '-list0 eprocessaddr #by _ETHREAD.Tcb.ThreadListEntry'
    print '-list1 eprocessaddr #by _ETHREAD.ThreadListEntry'

    
if __name__=='__main__':
    try:
        if len(sys.argv)<2:
            help()
            sys.exit(0)
            
        if sys.argv[1]=='-inspectall':
            inspectProcessHiddenThread()
                
        elif sys.argv[1]=='-inspectone':
            eprocessaddr=int(sys.argv[2], 16)
            inspectProcessHiddenThread(eprocessaddr)
    
        elif sys.argv[1]=='-list0':
            eprocessaddr=int(sys.argv[2], 16)
            threadlist=listThreadByTcbThreadListEntry(eprocessaddr)
            for i in threadlist:
                print 'ethread:%x tid:%d entry:%x' % (i.ethreadaddr, i.tid, i.entrypoint)
                    
        elif sys.argv[1]=='-list1':
            eprocessaddr=int(sys.argv[2], 16)
            threadlist=listThreadByThreadListEntry(eprocessaddr)
            for i in threadlist:
                print 'ethread:%x tid:%d entry:%x' % (i.ethreadaddr, i.tid, i.entrypoint)
                
        else:
            help()
    except Exception, err:
        print traceback.format_exc() 


