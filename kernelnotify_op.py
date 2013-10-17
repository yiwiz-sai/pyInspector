#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

def listCreateProcess():
    try:
        print '-'*10+'CreateProcess'+'-'*10
        notifyaddr=pykd.getOffset('nt!PspCreateProcessNotifyRoutine')
        count=pykd.getOffset('nt!PspCreateProcessNotifyRoutineCount')
        count=pykd.ptrPtr(count)
        try:
            excount=pykd.getOffset('nt!PspCreateProcessNotifyRoutineExCount') 
        except:
            excount=0
        count+=excount
        if is_2000():
            for i in xrange(count):
                funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                symbolname=pykd.findSymbol(source)
                print 'routine:%x %s' % (funcaddr, symbolname)
        else:
            if pykd.is64bitSystem():
                for i in xrange(count):
                    funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
            else:
                for i in xrange(count):
                    routine_block=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    funcaddr=pykd.ptrPtr(routine_block+g_mwordsize)
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
      
    except Exception, err:
        print traceback.format_exc()

def listCreateThread():
    try:
        print '-'*10+'CreateThread'+'-'*10
        notifyaddr=pykd.getOffset('nt!PspCreateThreadNotifyRoutine')
        count=pykd.getOffset('nt!PspCreateThreadNotifyRoutineCount')
        count=pykd.ptrPtr(count)
      
        
        if is_2000():
            for i in xrange(count):
                funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                symbolname=pykd.findSymbol(source)
                print 'routine:%x %s' % (funcaddr, symbolname)
        else:
            if pykd.is64bitSystem():
                for i in xrange(count):
                    funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
            else:
                for i in xrange(count):
                    routine_block=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    funcaddr=pykd.ptrPtr(routine_block+g_mwordsize)
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
      
    except Exception, err:
        print traceback.format_exc()


def listLoadImage():
    try:
        print '-'*10+'LoadImage'+'-'*10
        notifyaddr=pykd.getOffset('nt!PspLoadImageNotifyRoutine')
        count=pykd.getOffset('nt!PspLoadImageNotifyRoutineCount')
        count=pykd.ptrPtr(count)

        if is_2000():
            for i in xrange(count):
                funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                symbolname=pykd.findSymbol(source)
                print 'routine:%x %s' % (funcaddr, symbolname)
        else:
            if pykd.is64bitSystem():
                for i in xrange(count):
                    funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
            else:
                for i in xrange(count):
                    routine_block=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    funcaddr=pykd.ptrPtr(routine_block+g_mwordsize)
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
      
    except Exception, err:
        print traceback.format_exc()

def listCmpCallback():
    try:
        notifyaddr=pykd.getOffset('nt!CmpCallBackVector')
        count=pykd.getOffset('nt!CmpCallBackCount')
        count=pykd.ptrPtr(count)
      
        print '-'*10+'CmpCallback'+'-'*10
        if is_2000():
            for i in xrange(count):
                funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                symbolname=pykd.findSymbol(source)
                print 'routine:%x %s' % (funcaddr, symbolname)
        else:
            if pykd.is64bitSystem():
                for i in xrange(count):
                    funcaddr=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
            else:
                for i in xrange(count):
                    routine_block=pykd.ptrPtr(notifyaddr+i*g_mwordsize)&0xffffffffffffff8
                    funcaddr=pykd.ptrPtr(routine_block+g_mwordsize)
                    symbolname=pykd.findSymbol(funcaddr)
                    print 'routine:%x %s' % (funcaddr, symbolname)
      
    except Exception, err:
        print traceback.format_exc()

def listBugCheckCallback():
    try:
        print '-'*10+'BugCheckCallback'+'-'*10
        head=pykd.getOffset('nt!KeBugCheckCallbackListHead')
        next=head
        while 1:
            next=pykd.ptrPtr(next)
            if next==head:
                break
            funcaddr=pykd.ptrPtr(next+g_mwordsize*2)
            symbolname=pykd.findSymbol(funcaddr)
            print 'routine:%x %s' % (funcaddr, symbolname)
    except Exception, err:
        print traceback.format_exc()

def listBugCheckReasonCallback():
    try:
        print '-'*10+'BugCheckReasonCallback'+'-'*10
        head=pykd.getOffset('nt!KeBugCheckReasonCallbackListHead')
        next=head
        while 1:
            next=pykd.ptrPtr(next)
            if next==head:
                break
            funcaddr=pykd.ptrPtr(next+g_mwordsize*2)
            symbolname=pykd.findSymbol(funcaddr)
            print 'routine:%x %s' % (funcaddr, symbolname)
    except Exception, err:
        print traceback.format_exc()
        
def listSeFileSystem():
    try:
        print '-'*10+'SeFileSystem'+'-'*10
        head=pykd.getOffset('nt!SeFileSystemNotifyRoutinesHead')
        next=head
        while 1:
            next=pykd.ptrPtr(next)
            if not next:
                break
            funcaddr=pykd.ptrPtr(next+g_mwordsize)
            symbolname=pykd.findSymbol(funcaddr)
            print 'routine:%x %s' % (funcaddr, symbolname)
    except Exception, err:
        print traceback.format_exc()


def listFsNotifyChange():
    try:
        print '-'*10+'FsNotifyChange'+'-'*10
        head=pykd.getOffset('nt!IopFsNotifyChangeQueueHead')
        next=head
        while 1:
            next=pykd.ptrPtr(next)
            if next==head:
                break
            dirverobjectaddr=pykd.ptrPtr(next+g_mwordsize*2)
            funcaddr=pykd.ptrPtr(next+g_mwordsize*3)
            try:
                driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', dirverobjectaddr) 
                drivername=pykd.loadUnicodeString(driverobject.DriverName)
            except Exception, err:
                drivername=''
            symbolname=pykd.findSymbol(funcaddr)
            print 'routine:%x %s driver:%s' % (funcaddr, symbolname, drivername)
    except Exception, err:
        print traceback.format_exc()
        
def listPlugPlay():
    try:
        print '-'*10+'PlugPlay'+'-'*10
        table=pykd.getOffset('nt!IopDeviceClassNotifyList')
        for i in xrange(13):
            head=table+g_mwordsize*i*2
            next=head
            while 1:
                next=pykd.ptrPtr(next)
                if next==head:
                    break
                funcaddr=pykd.ptrPtr(next+g_mwordsize*5)
                symbolname=pykd.findSymbol(funcaddr)
                print 'routine:%x %s' % (funcaddr, symbolname)
    except Exception, err:
        print traceback.format_exc()


def listIopTimer():
    try:
        print '-'*10+'IopTimer'+'-'*10
        head=pykd.getOffset('nt!IopTimerQueueHead')
        next=head
        while 1:
            next=pykd.ptrPtr(next)
            if next==head:
                break
            funcaddr=pykd.ptrPtr(next+g_mwordsize*2)
            symbolname=pykd.findSymbol(funcaddr)
            print 'routine:%x %s' % (funcaddr, symbolname)
    except Exception, err:
        print traceback.format_exc()

def listShutdown():
    try:
        print '-'*10+'Shutdown'+'-'*10
        
        IRP_MJ_SHUTDOWN=0x10
        #define IRP_MJ_SHUTDOWN                 0x10
        head=pykd.getOffset('nt!IopNotifyShutdownQueueHead')
        next=head
        while 1:
            next=pykd.ptrPtr(next)
            if next==head:
                break
            try:
                deviceobjectaddr=pykd.ptrPtr(next+g_mwordsize*2)
                deviceobject=pykd.typedVar('nt!_DEVICE_OBJECT', deviceobjectaddr) 
                driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', int(deviceobject.DriverObject))  
                funcaddr=pykd.ptrPtr(driverobject.MajorFunction+g_mwordsize*IRP_MJ_SHUTDOWN)
                symbolname=pykd.findSymbol(funcaddr)
                print 'routine:%x %s' % (funcaddr, symbolname)
            except Exception, err:
                pass
    except Exception, err:
        print traceback.format_exc()

    
def listKernelNotifyRoutine():
    listCreateProcess()
    listCreateThread()
    listLoadImage()
    listCmpCallback()
    listBugCheckCallback()
    listBugCheckReasonCallback()
    listSeFileSystem()
    listFsNotifyChange()
    listPlugPlay()
    listIopTimer()
    listShutdown()

if __name__=='__main__':
    listKernelNotifyRoutine()
    pass
