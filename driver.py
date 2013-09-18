#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
import windbgCmdHelper

class DriverInfo(object):
    def __init__(self, name='', filepath='', driverobject=0,  baseaddr=0, modulesize=0, deviceobjectlist=[], dispatchfuncs=[], fastiofuncs=[]):
        self.name=name.lower()
        self.filepath=filepath.lower()
        self.baseaddr='%x' % int(str(baseaddr), 16)
        self.driverobject='%x' % int(str(driverobject), 16)
        self.modulesize='%x' % int(str(modulesize), 16)
        self.deviceobjectlist=map(lambda x:'%x' % int(str(x), 16), deviceobjectlist)
        self.dispatchfuncs=map(lambda x:[x[0], '%x' % int(str(x[1]), 16)], dispatchfuncs)
        self.fastiofuncs=map(lambda x:[x[0], '%x' % int(str(x[1]), 16)], fastiofuncs)
        
class DeviceInfo(object):
    def __init__(self, driverobject=0, deviceobject=0,  upperdeviceobject=0, lowerdeviceobject=0):
        self.driverobject='%x' % int(str(driverobject), 16)
        self.deviceobject='%x' % int(str(deviceobject), 16)
        self.upperdeviceobject='%x' % int(str(upperdeviceobject), 16)
        self.lowerdeviceobject='%x' % int(str(lowerdeviceobject), 16)
        
def getDeviceInfo(deviceobject):
    try:
        DeviceObject=deviceobject
        UpperDeviceObject=0
        LowerDeviceObject=0
        DriverObject=0
        cmdline=r'!devobj %s' % str(deviceobject)
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        type=''
        for i in r:
            i=i.strip()
            if i.startswith('Device object'):
                type='Device object'
                continue
            elif i.startswith('AttachedDevice (Upper) '):
                d=i[len('AttachedDevice (Upper) '):]
                UpperDeviceObject=d.split(' ')[0]
                continue
            elif i.startswith('AttachedTo (Lower) '):
                d=i[len('AttachedTo (Lower) '):]
                LowerDeviceObject=d.split(' ')[0]
                continue
            if type=='Device object':
                a=i.split(' ')
                DriverObject=a[-1]
                type=''
        
        a=DeviceInfo(driverobject=DriverObject,  deviceobject=DeviceObject, upperdeviceobject=UpperDeviceObject, lowerdeviceobject=LowerDeviceObject)
        return a
    except Exception, err:
        print err
        return None

def getDriverInfo(driverobject):
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
                    pos=data.find('_UNICODE_STRING')
                    if pos!=-1:
                        info['DriverName']=data[pos+len('_UNICODE_STRING'):].strip()
                    break
        
        global g_fastinspect
        if g_fastinspect:
            cmdline=r'dt _LDR_DATA_TABLE_ENTRY %s' % str(driverobject)
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
                        pos=data.find('_UNICODE_STRING')
                        if pos!=-1:
                            info['FullDllName']=data[pos+len('_UNICODE_STRING'):].strip()
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

g_fastinspect=True
g_drivers={}
def  ListDriversByDirectoryObject(dirname=r'\\'):
    global g_drivers
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
            ListDriversByDirectoryObject(childname)
            
        elif type=='Device':
            deviceinfo=getDeviceInfo(obj)
            drvobj=deviceinfo.driverobject 
            if drvobj in g_drivers:
                continue
            g_drivers[drvobj]=[]
            driverinfo=getDriverInfo(drvobj)
            g_drivers[drvobj].append(driverinfo)
            
        elif type=='Driver':
            driverinfo=getDriverInfo(obj)
            drvobj=driverinfo.driverobject 
            if drvobj not in g_drivers:
                g_drivers[drvobj]=[]
            g_drivers[drvobj].append(driverinfo)

def  ListDriversByZwQueryDriver():
    return []
    
def  ListDriversByDriverSection():
    return []

def ListDrivers(fastinspect=True):
    global g_drivers, g_fastinspect
    start_time=time.time()
    g_drivers={}
    g_fastinspect=fastinspect
    ListDriversByDirectoryObject()
    print len(g_drivers)
    print time.time()-start_time
    return
    driverlist=[]
    driverlist+=ListDriversByZwQueryDriver()
    driverlist+=ListDriversByDriverSection()
    print len(driverlist)
    
if __name__=='__main__':
    #extractDriverInfo('8631f918')
    #extractDeviceInfo('85d967a0')
    ListDrivers()

