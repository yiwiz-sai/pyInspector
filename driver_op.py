#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
from common import *
from directory_op  import *

MajorFunction=\
    [
        'IRP_MJ_CREATE', 
        'IRP_MJ_CREATE_NAMED_PIPE', 
        'IRP_MJ_CLOSE', 
        'IRP_MJ_READ', 
        'IRP_MJ_WRITE', 
        'IRP_MJ_QUERY_INFORMATION', 
        'IRP_MJ_SET_INFORMATION', 
        'IRP_MJ_QUERY_EA',
        'IRP_MJ_SET_EA', 
        'IRP_MJ_FLUSH_BUFFERS', 
        'IRP_MJ_QUERY_VOLUME_INFORMATION', 
        'IRP_MJ_SET_VOLUME_INFORMATION', 
        'IRP_MJ_DIRECTORY_CONTROL', 
        'IRP_MJ_FILE_SYSTEM_CONTROL', 
        'IRP_MJ_DEVICE_CONTROL', 
        'IRP_MJ_INTERNAL_DEVICE_CONTROL', 
        'IRP_MJ_SHUTDOWN', 
        'IRP_MJ_LOCK_CONTROL', 
        'IRP_MJ_CLEANUP', 
        'IRP_MJ_CREATE_MAILSLOT', 
        'IRP_MJ_QUERY_SECURITY', 
        'IRP_MJ_SET_SECURITY', 
        'IRP_MJ_POWER', 
        'IRP_MJ_SYSTEM_CONTROL', 
        'IRP_MJ_DEVICE_CHANGE', 
        'IRP_MJ_QUERY_QUOTA', 
        'IRP_MJ_SET_QUOTA', 
        'IRP_MJ_PNP', 
        'IRP_MJ_PNP_POWER', 
        'IRP_MJ_MAXIMUM_FUNCTION', 
    ]
    
class DriverInfo(object):
    def init1(self, driverobjectaddr):
        try:
            driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', driverobjectaddr) 
            ldr=int(driverobject.DriverSection)
            if self.init2(ldr):
                self.driverobjectaddr=int(driverobject)
                return True
            
            self.driverobjectaddr=int(driverobject)
            filepath=revise_filepath(pykd.loadUnicodeString(driverobject.DriverName))
            self.filepath, self.name=guess_filepath(filepath)

            self.baseaddr=int(driverobject.DriverStart)
            self.modulesize=int(driverobject.DriverSize)
            self.entrypoint=0
            return True
        except Exception, err:
            print traceback.format_exc()          
            return False
        
    def init2(self, ldr):
        try:
            if not int(ldr):
                return False
        
            DriverSection=pykd.typedVar('nt!_LDR_DATA_TABLE_ENTRY', ldr)
            self.driverobjectaddr=0
            filepath=revise_filepath(pykd.loadUnicodeString(DriverSection.FullDllName))
            name=pykd.loadUnicodeString(DriverSection.BaseDllName)
            self.filepath, self.name=guess_filepath(filepath, name)
            
            self.baseaddr=int(DriverSection.DllBase)
            self.modulesize=int(DriverSection.SizeOfImage)
            self.entrypoint=int(DriverSection.EntryPoint)
            return True        
        except Exception, err:
            print traceback.format_exc()
            return False
    
def listDriverByDirectoryObject():
    driverlist={}
    try:
        def list_callback(obj, type, driverlist):
            try:
                if type=='Driver':
                    driverobjectaddr=int(obj, 16)
                elif type=='Device':
                    deviceobjectaddr=int(obj, 16)
                    deviceobject=pykd.typedVar('nt!_DEVICE_OBJECT', deviceobjectaddr)
                    driverobjectaddr=int(deviceobject.DriverObject)
                else:
                    return True
                
                if driverobjectaddr not in driverlist:
                    info=DriverInfo()
                    if info.init1(driverobjectaddr):
                        driverlist[driverobjectaddr]=info
                else:
                    pass
            except Exception, err:
                print traceback.format_exc()
                
            return True
        crawl_object_by_directory(list_callback, driverlist)
        
    except Exception, err:
        print traceback.format_exc()     
    return driverlist.values()

def listDriverByPsLoadedModuleList():
    driverlist=[]
    try:
        PsLoadedModuleList=pykd.getOffset('nt!PsLoadedModuleList')
        l=pykd.typedVarList(PsLoadedModuleList, 'nt!_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks')
        for i in l:
            if int(i.InLoadOrderLinks)==PsLoadedModuleList:
                continue
            info=DriverInfo()
            if info.init2(i):
                driverlist.append(info)

    except Exception, err:
        print traceback.format_exc()
    return driverlist

def inspectDispatchRoutine(driverobjectaddr=None):
    try:
        if driverobjectaddr:
            driverinfo=DriverInfo()
            if not driverinfo.init1(driverobjectaddr):
                print 'fail to get driver info'
                return

            driverlist=[driverinfo]
        else:
            driverlist=listDriverByDirectoryObject()
        
        for driverinfo in driverlist:
            try:
                startaddr=driverinfo.baseaddr
                endaddr=driverinfo.baseaddr+driverinfo.modulesize
                driverobjectaddr=driverinfo.driverobjectaddr
                driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', driverobjectaddr) 
                print '='*10, 'drvobj:%x %s' % (driverobjectaddr,driverinfo.filepath),'='*10
                for i in xrange(28):
                    funcaddr=pykd.ptrPtr(driverobject.MajorFunction+i*g_mwordsize)
                    symbolname=pykd.findSymbol(funcaddr)
                    if funcaddr<startaddr or funcaddr>=endaddr:
                        if symbolname.find('+')!=-1:
                            print '%d %s %x %s maybe hooked!!!!!' % (i, MajorFunction[i], funcaddr, symbolname)
                        else:
                            print '%d %s %x %s' % (i, MajorFunction[i], funcaddr, symbolname)
                    else:
                        print '%d %s %x %s' % (i, MajorFunction[i], funcaddr, symbolname)
        
            except Exception, err:
                print traceback.format_exc()
                
    except Exception, err:
        print traceback.format_exc() 

def listDriverDevice(driverobjectaddr):
    try:
        driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', driverobjectaddr) 
        deviceobject=driverobject.DeviceObject
        while 1:
            if not int(deviceobject):
                break
            print '%x' % int(deviceobject)
            deviceobject=deviceobject.NextDevice
            
    except Exception, err:
        print traceback.format_exc()

def help():
    print '-inspectalldispatch'
    print '-inspectdispatchroutine driverobjectaddr'
    print '-listdevice driverobjectaddr'
    print '-list0 #by listDriverByPsLoadedModuleList'
    print '-list1 #by listDriverByDirectoryObject'
    
if __name__=='__main__':
    try:
        if len(sys.argv)<2:
            help()
            sys.exit(0)
            
        if sys.argv[1]=='-inspectalldispatchroutine':
            inspectDispatchRoutine()
            
        elif sys.argv[1]=='-inspectdispatchroutine':
            driverobjectaddr=int(sys.argv[2], 16)
            inspectDispatchRoutine(driverobjectaddr)
        
        elif sys.argv[1]=='-listdevice':
            driverobjectaddr=int(sys.argv[2], 16)
            listDriverDevice(driverobjectaddr)
        
        elif sys.argv[1]=='-list0':
            driverlist=listDriverByPsLoadedModuleList()
            for i in driverlist:
                print 'drvobj:%x base:%x size:%x entry:%x %s %s' % (i.driverobjectaddr, i.baseaddr, i.modulesize,i.entrypoint, i.name, i.filepath)

        elif sys.argv[1]=='-list1':
            driverlist=listDriverByDirectoryObject()
            for i in driverlist:
                print 'drvobj:%x base:%x size:%x entry:%x %s %s' % (i.driverobjectaddr, i.baseaddr, i.modulesize,i.entrypoint, i.name, i.filepath)
        
        else:
            help()

    except Exception, err:
        print traceback.format_exc() 
