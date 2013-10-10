#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

class ThreadInfo(object):
    def __init__(self, ethread=None):
        super(ThreadInfo, self).__init__()
        self.ethread=int(ethread)
        self.tid=int(ethread.Cid.UniqueThread)
        self.startaddr=int(ethread.StartAddress)
        
mmhighestuseraddress=pykd.getOffset('nt!MmHighestUserAddress')
def add_thread(ethread_table, ethreadobj):
    try:
        ethreadaddr=int(ethreadobj)
        if ethreadaddr in ethread_table:
            return
        if ethreadaddr<mmhighestuseraddress:
            #print 'invalid process:', hex(eprocessobj), 'pid:', int(eprocessobj.UniqueProcessId)
            ethread_table[ethreadaddr]=None
        else:
            #print hex(eprocessobj)
            ethread_table[ethreadaddr]=ThreadInfo(ethreadobj)
            
    except Exception, err:
        print traceback.format_exc()
        
def listThread(eprocessaddr=None):
    ethread_table={}
    try:
        if not eprocessaddr:
            PsActiveProcessHead=pykd.getOffset('nt!PsActiveProcessHead')
            entry=pykd.ptrPtr(PsActiveProcessHead)
            eprocessobj=pykd.containingRecord(entry, 'nt!_EPROCESS', 'ActiveProcessLinks')
            eprocessaddr=int(eprocessobj)
        else:
            eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
            
        threadList=pykd.typedVarList(eprocessobj.ThreadListHead, 'nt!_ETHREAD', 'ThreadListEntry')
        for i in threadList:
            add_thread(ethread_table, i)
        
        threadList=pykd.typedVarList(eprocessobj.Pcb.ThreadListHead, 'nt!_ETHREAD', 'Tcb.ThreadListEntry')
        for i in threadList:
            add_thread(ethread_table, i)

    except Exception, err:
        print traceback.format_exc()

    l=filter(lambda x:x!=None, ethread_table.values())
    l.sort(key=lambda x:x.tid)
    return l
    
if __name__=='__main__':
    starttime=time.time()
    l=listThread()
    print 'ethread tid startaddr'
    print '='*30
    for i in l:
        print '%x %d %x' % (i.ethread, i.tid, i.startaddr)
    print 'number:', len(l), 'cost time:', time.time()-starttime
    

