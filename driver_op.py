#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
from common import *
from directory_op  import *

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
    driverlist=[]
    try:
        def list_callback(obj, type, driverlist):
            if type=='Driver':
                driverobjectaddr=int(obj, 16)
                info=DriverInfo()
                if info.init1(driverobjectaddr):
                    driverlist.append(info)
                    
            return True
        crawl_object_by_directory(list_callback, driverlist)
        
    except Exception, err:
        print traceback.format_exc()     
    return driverlist

def listDriverByPsLoadedModuleList():
    driverlist=[]
    try:

        PsLoadedModuleList=pykd.getOffset('nt!PsLoadedModuleList')
        l=pykd.typedVarList(PsLoadedModuleList, 'nt!_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks')
        for i in l:
            info=DriverInfo()
            if info.init2(i):
                driverlist.append(info)

    except Exception, err:
        print traceback.format_exc()
    return driverlist

def inspectDispatchRoutine(driverinfo):
    try:
        driverobjectaddr=driverinfo.driverobjectaddr
        if not int(driverobjectaddr):
            return
        startaddr=driverinfo.baseaddr
        endaddr=driverinfo.baseaddr+driverinfo.modulesize
        driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', driverobjectaddr) 
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
        print '='*10, 'drvobj:%x %s' % (driverobjectaddr,driverinfo.filepath),'='*10
        for i in xrange(28):
            funcaddr=pykd.ptrPtr(driverobject.MajorFunction+i*g_mwordsize)
            symbolname=pykd.findSymbol(funcaddr)
            if funcaddr<startaddr or funcaddr>=endaddr:
                print '%d %s %x %s maybe hooked!!!!!' % (i, MajorFunction[i], funcaddr, symbolname)
            else:
                print '%d %s %x %s' % (i, MajorFunction[i], funcaddr, symbolname)

    except Exception, err:
        print traceback.format_exc()     

def listDriverDevices(driverobjectaddr):
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

def inspectAllDispatchRoutine():
    funclist=\
    [
        listDriverByPsLoadedModuleList, 
        listDriverByDirectoryObject, 
    ]
    for func in funclist:
        driverlist=func()
        for i in driverlist:
            inspectDispatchRoutine(i)
    pass
    
def inspectHiddenDriver():
    funclist=\
    [
        listDriverByPsLoadedModuleList, 
        listDriverByDirectoryObject, 
    ]
    print 'driverobject baseaddr size entrypoint name filepath'
    for func in funclist:
        print '='*10+func.func_name+'='*10
        driverlist=func()
        for i in driverlist:
            print '%x %x %x %x %s %s' % (i.driverobjectaddr, i.baseaddr, i.modulesize,i.entrypoint, i.name, i.filepath)

if __name__=='__main__':
    if sys.argv[1]=='alldriver':
        inspectHiddenDriver()
    elif sys.argv[1]=='alldispatch':
        inspectAllDispatchRoutine()
    else:
        driverobjectaddr=int(sys.argv[1], 16)
        info=DriverInfo()
        if info.init1(driverobjectaddr):
            inspectDispatchRoutine(info)
