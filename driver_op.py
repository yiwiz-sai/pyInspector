#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
import windbgCmdHelper

def getDriverInfo(driverobject, fastinspect=False):
    info={'DriverObject':str(driverobject)}
    try:
        cmdline=r'dt _driver_object %s' % str(driverobject)
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        for i in r:
            i=i.strip()
            if i.startswith('+'):
                i=i.split(':')
                j=i[0].split(' ')
                name=j[1]
                data=i[1].strip()
                if data.startswith('?'):
                    continue
                if name=='DriverStart':
                    DriverStart=data.split(' ')[0]
                    info['DriverStart']=DriverStart
                elif name=='DriverSize':
                    DriverSize=data.split(' ')[0]
                    info['DriverSize']=DriverSize
                elif name=='DriverSection':
                    DriverSection=data.split(' ')[0]
                    info['DriverSection']=DriverSection
                elif name=='DriverName':
                    info['DriverName']=windbgCmdHelper.get_unicode_string(data)
                    break
        
        if not fastinspect:
            cmdline=r'dt _LDR_DATA_TABLE_ENTRY %s' % str(DriverSection)
            r=pykd.dbgCommand(cmdline)
            r=r.splitlines()
            for i in r:
                i=i.strip()
                if i.startswith('+'):
                    i=i.split(':')
                    j=i[0].split(' ')
                    name=j[1]
                    data=i[1].strip()
                    if data.startswith('?'):
                        continue
                    if name=='DllBase':
                        DllBase=data.split(' ')[0]
                        info['DllBase']=DllBase
                    elif name=='SizeOfImage':
                        SizeOfImage=data.split(' ')[0]
                        info['SizeOfImage']=SizeOfImage
                    elif name=='FullDllName':
                        info['FullDllName']=windbgCmdHelper.get_unicode_string(data)
                        break
            
            cmdline=r'!drvobj %s 3' % str(driverobject)
            r=pykd.dbgCommand(cmdline)
            r=r.splitlines()
            type=''
            for i in r:
                i=i.strip()
                if i.startswith('Device Object list'):
                    type='Device Object list'
                    continue
                elif i.startswith('Dispatch routines'):
                    type='Dispatch routines'
                    continue
                elif i.startswith('Fast I/O routines'):
                    type='Fast I/O routines'
                    continue
    
                if type=='Device Object list':
                    a=i.split(' ')
                    info['DeviceObjects']=filter(lambda x:x!='', a)
                    type=''
                elif type=='Dispatch routines' or type=='Fast I/O routines':
                    if i=='':
                        type=''
                    else:
                        a=i.split(' ')
                        a=filter(lambda x:x!='', a)
                        if type not in info:
                            info[type]=[]
                        if type=='Dispatch routines':
                            funcaddr, symbolname=a[-1].split('\t')
                            info[type].append([a[1], funcaddr, symbolname])
                        else:
                            info[type].append([a[0], funcaddr, symbolname])
        
        name=info.get('DriverName','')
        filepath=info.get('FullDllName', '')
        driverobject=info.get('DriverObject', 0)
        baseaddr=info.get('DriverStart', 0)
        if baseaddr=='(null)':
            baseaddr=0
        modulesize=info.get('SizeOfImage', 0)
        if modulesize=='(null)':
            modulesize=0
        deviceobjectlist=info.get('DeviceObjects', [])
        dispatchfuncs=info.get('Dispatch routines', [])
        fastiofuncs=info.get('Fast I/O routines', [])
        a=DriverInfo(name=name, filepath=filepath, driverobject=driverobject, baseaddr=baseaddr, modulesize=modulesize, deviceobjectlist=deviceobjectlist, dispatchfuncs=dispatchfuncs, fastiofuncs=fastiofuncs)
        return a
    except Exception, err:
        print err
        return None

    
def ListDriversByDirectoryObject(drivers, dirname=r'\\', fastinspect=False):
    cmdline=r'!object '+dirname
    print cmdline
    r=pykd.dbgCommand(cmdline)
    r=r.splitlines()
    startlist=0
    for i in r:
        i=i.lstrip()
        if i.startswith('--'):
            startlist=1
            continue
            
        if not startlist:
            continue
        data=i.split()
        if len(data)>3:
            obj=data[1]
            type=data[2]
            name=data[3]
        else:
            obj=data[0]
            type=data[1]
            name=data[2]
        
        if type=='Directory':
            #cmdline=r'!object '+obj
            childname=dirname+name+r'\\'
            ListDriversByDirectoryObject(drivers, childname, fastinspect)
            
        elif type=='Device':
            deviceinfo=getDeviceInfo(obj)
            drvobj=deviceinfo.driverobject 
            if drvobj in drivers:
                continue
            drivers[drvobj]=[]
            driverinfo=getDriverInfo(drvobj)
            drivers[drvobj].append(driverinfo)
            
        elif type=='Driver':
            driverinfo=getDriverInfo(obj, fastinspect)
            drvobj=driverinfo.driverobject 
            if drvobj not in drivers:
                drivers[drvobj]=[]
            drivers[drvobj].append(driverinfo)
    
    return drivers
    
def  ListDriversByZwQueryDriver(drivers):
    return []
    
def  ListDriversByDriverSection(drivers):
    
    return []

def ListDrivers(fastinspect=False):
    start_time=time.time()
    drivers={}
    ListDriversByDirectoryObject(drivers, fastinspect=fastinspect)
    ListDriversByZwQueryDriver(drivers)
    ListDriversByDriverSection(drivers)
    
    n=0
    for l in drivers.values():
        for i in l:
            print '='*20
            print i.name, i.filepath, i.baseaddr, i.driverobject, i.modulesize, i.deviceobjectlist
            print i.dispatchfuncs
            print i.fastiofuncs
            n+=1
    print time.time()-start_time
    print n
    
if __name__=='__main__':
    ListDrivers(False)

