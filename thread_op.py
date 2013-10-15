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
        self.startaddr=int(ethreadobj.StartAddress)
        
def inspectHiddenThread(eprocessinfo):
    threadlist={}
    hiddenthreadlist=[]
    try:
        eprocessaddr=eprocessinfo.eprocessaddr
        cmdline='.process /P %x;.reload;' % eprocessaddr
        r=pykd.dbgCommand(cmdline)
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        threadList=pykd.typedVarList(eprocessobj.ThreadListHead, 'nt!_ETHREAD', 'ThreadListEntry')
        for i in threadList:
            if int(i) not in threadlist:
                info=ThreadInfo(i)
                symbolname=pykd.findSymbol(info.startaddr)
                if symbolname.find('!')==-1:
                    hiddenthreadlist.append(info)

                threadlist[int(i)]=1

        threadList=pykd.typedVarList(eprocessobj.Pcb.ThreadListHead, 'nt!_ETHREAD', 'Tcb.ThreadListEntry')
        for i in threadList:
            if int(i) not in threadlist:
                threadlist[int(i)]=ThreadInfo(i)
        
        if hiddenthreadlist:
            print '!'*10, 'process:%x pid:%d %s' % (eprocessaddr, eprocessinfo.pid, eprocessinfo.fullpath), '!'*10
            for i in hiddenthreadlist:
                print 'ethread:%x tid:%d entry:%x' % (i.ethreadaddr, i.tid, i.startaddr)
        else:
            print '='*10, 'process:%x pid:%d %s has no hidden thread' % (eprocessaddr, eprocessinfo.pid, eprocessinfo.fullpath), '='*10
    except Exception, err:
        print traceback.format_exc()

    
from process_op import *
def inspectAllProcessHiddenThread():
    processlist=listProcessByPsActiveProcessHead()
    for i in processlist:
        inspectHiddenThread(i)
    print 
    print 'inspect completely'
    
if __name__=='__main__':
    if sys.argv[1]=='all':
        inspectAllProcessHiddenThread()
    else:
        eprocessaddr=int(sys.argv[1], 16)
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        info=ProcessInfo()
        if info.init(eprocessaddr):
            inspectHiddenThread(info)

    

