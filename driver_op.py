#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
from common import *
from directory_op  import *
class DriverInfo(object):
    def __init__(self, name='', filepath='', driverobject=0, entrypoint=0,  baseaddr=0, modulesize=0):
        self.name=name.lower()
        self.filepath=filepath.lower()
        self.baseaddr=baseaddr
        self.driverobject=driverobject
        self.modulesize=modulesize
        self.entrypoint=entrypoint

def add_driver2(driver_table, ldr):
    try:
        ldr=int(ldr)
        if ldr in driver_table:
            return
        
        DriverSection=pykd.typedVar('nt!_LDR_DATA_TABLE_ENTRY', ldr)
        filepath=pykd.loadUnicodeString(DriverSection.FullDllName)
        name=pykd.loadUnicodeString(DriverSection.BaseDllName)
        baseaddr=int(DriverSection.DllBase)
        modulesize=int(DriverSection.SizeOfImage)
        entrypoint=int(DriverSection.EntryPoint)
        print ldr, name
        driver_table[ldr]=DriverInfo(name=name, filepath=filepath,  entrypoint=entrypoint, baseaddr=baseaddr, modulesize=modulesize)
    except Exception, err:
        print traceback.format_exc()          
    
def add_driver(driver_table, driverobjectaddr):
    try:
        driverobject=pykd.typedVar('nt!_DRIVER_OBJECT', driverobjectaddr) 
        ldr=int(driverobject.DriverSection)
        if ldr==0:
            filepath=pykd.loadUnicodeString(driverobject.DriverName)
            name=os.path.basename(filepath)
            baseaddr=int(driverobject.DriverStart)
            modulesize=int(driverobject.DriverSize)
            driver_table[int(driverobject)]=DriverInfo(name=name, filepath=filepath, driverobject=driverobjectaddr, baseaddr=baseaddr, modulesize=modulesize)
            return
            
        if ldr in driver_table:
            return
        
        DriverSection=pykd.typedVar('nt!_LDR_DATA_TABLE_ENTRY', ldr)
        filepath=pykd.loadUnicodeString(DriverSection.FullDllName)
        name=pykd.loadUnicodeString(DriverSection.BaseDllName)
        baseaddr=int(DriverSection.DllBase)
        modulesize=int(DriverSection.SizeOfImage)
        entrypoint=int(DriverSection.EntryPoint)
        driver_table[ldr]=DriverInfo(name=name, filepath=filepath, driverobject=driverobjectaddr,  entrypoint=entrypoint, baseaddr=baseaddr, modulesize=modulesize)
    except Exception, err:
        print traceback.format_exc()          
            
def listDriversByDirectoryObject(driver_table):
    try:
        def list_callback(obj, type, driver_table):
            if type=='Driver':
                driverobjectaddr=int(obj, 16)
                add_driver(driver_table, driverobjectaddr)
            return True
        crawl_object_by_directory(list_callback, driver_table)
        return
    except Exception, err:
        print traceback.format_exc()          

def listDriversByPsLoadedModuleList(driver_table):
    try:
        PsLoadedModuleList=pykd.getOffset('nt!PsLoadedModuleList')
        l=pykd.typedVarList(PsLoadedModuleList, 'nt!_LDR_DATA_TABLE_ENTRY', 'InLoadOrderLinks')
        for i in l:
            add_driver2(driver_table, i)

    except Exception, err:
        print traceback.format_exc()     
        
def ListDrivers():
    driver_table={}
    listDriversByDirectoryObject(driver_table)
    listDriversByPsLoadedModuleList(driver_table)
    return driver_table.values()

def getDevices(driverobjectaddr):
    pass

if __name__=='__main__':
    starttime=time.time()
    l=ListDrivers()
    print 'driverobject baseaddr size entrypoint name filepath'
    print '='*30
    for i in l:
        print '%x %x %x %x %s %s' % (i.driverobject, i.baseaddr, i.modulesize,i.entrypoint, i.name, i.filepath)
    print 'number:', len(l), 'cost time:', time.time()-starttime
