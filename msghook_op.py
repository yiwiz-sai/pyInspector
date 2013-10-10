#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

g_msg=\
{
    0:"WH_JOURNALRECORD", 
    1:"WH_JOURNALPLAYBACK", 
    2:"WH_KEYBOARD", 
    3:"WH_GETMESSAGE", 
    4:"WH_CALLWNDPROC", 
    5:"WH_CBT", 
    6:"WH_SYSMSGFILTER", 
    7:"WH_MOUSE", 
    8:"WH_HARDWARE", 
    9:"WH_DEBUG", 
    10:"WH_SHELL", 
    11:"WH_FOREGROUNDIDLE", 
    12:"WH_CALLWNDPROCRET", 
    13:"WH_KEYBOARD_LL", 
    14:"WH_MOUSE_LL", 
    0xffffffffffffffff:"WH_MSGFILTER", 
}

class MsgInfo(object):
    def __init__(self, handle=-1, pid=-1, tid=-1, msgtype=None, funcoffset=0, bGlobal=0, processpath=''):
        self.handle=handle
        self.pid=pid
        self.tid=tid
        self.msg=g_msg.get(msgtype,'unknown:'+str(msgtype))
        self.funcoffset=funcoffset
        self.bGlobal=bGlobal
        self.processpath=processpath

def listMsgHook():
    msglist=[]
    try:
        gSharedInfo=pykd.getOffset('win32k!gSharedInfo')
        serverinfo=pykd.ptrPtr(gSharedInfo)
        aheList=pykd.ptrPtr(gSharedInfo+g_mwordsize)
        if is_2000() or is_xp():
            count=pykd.ptrPtr(serverinfo+g_mwordsize*2)
        else:
            count=pykd.ptrPtr(serverinfo+g_mwordsize*1)
        
        for i in xrange(count):
            entry=aheList+i*3*g_mwordsize
            phook=pykd.ptrPtr(entry) #head
            type=pykd.ptrByte(entry+2*g_mwordsize)
            if type!=5:
                continue
            
            try:
                handle=pykd.ptrPtr(phook)
                msgtype=pykd.ptrPtr(phook+6*g_mwordsize)
                funcoffset=pykd.ptrPtr(phook+7*g_mwordsize)
                flags=pykd.ptrPtr(phook+8*g_mwordsize)
                if flags&1:
                    bGlobal=1
                else:
                    bGlobal=0
                    
                pti=pykd.ptrPtr(phook+2*g_mwordsize)
                threadobjectaddr=pykd.ptrPtr(pti)
                threadobject=pykd.typedVar('nt!_ETHREAD', threadobjectaddr)
                pid=int(threadobject.Cid.UniqueProcess)
                tid=(threadobject.Cid.UniqueThread)
                try:
                    processobject=pykd.typedVar('nt!_EPROCESS', threadobject.ThreadsProcess)
                except Exception, err:
                    processobject=pykd.typedVar('nt!_EPROCESS', threadobject.Tcb.Process)
                processpath=pykd.loadUnicodeString(processobject.SeAuditProcessCreationInfo.ImageFileName.Name)
                
                msginfo=MsgInfo(handle=handle, pid=pid, tid=tid, msgtype=msgtype, funcoffset=funcoffset, bGlobal=bGlobal, processpath=processpath)
                msglist.append(msginfo)

            except Exception, err:
                print err
    except Exception, err:
        print traceback.format_exc()
    
    return msglist
    
if __name__=='__main__':
    n1=n2=0
    r=listMsgHook()
    print 'pid tid handle funcoffset msg bGlobal processpath'
    for i in r:
        print '%d %d 0x%x 0x%x %s %d %s' % (i.pid, i.tid, i.handle, i.funcoffset, i.msg, i.bGlobal, i.processpath)
        if i.bGlobal:
            n2+=1
        else:
            n1+=1
    print 'local hook number:%d, global hook number:%d' % (n1, n2)
