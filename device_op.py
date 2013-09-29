#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
from struct_info import *
def getDeviceInfo(deviceobject):
    info={}
    try:
        cmdline=r'dt _device_object %s' % deviceobject
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        for i in r:
            i=i.strip()
            if i.startswith('+'):
                i=i.split(':')
                j=i[0].split(' ')
                name=j[1]
                data=i[1].strip()
                if name=='DriverObject':
                    if data.find('(null)')!=-1:
                        info['DriverObject']='0'
                    else:
                        info['DriverObject']=data.split(' ')[0]
                elif name=='AttachedDevice':
                    if data.find('(null)')!=-1:
                        info['AttachedDevice']='0'
                    else:
                        info['AttachedDevice']=data.split(' ')[0]
                elif name=='Timer':
                    if data.find('(null)')!=-1:
                        info['Timer']='0'
                    else:
                        info['Timer']=data.split(' ')[0]
        if not deviceobject.startswith('0x'):
            deviceobject='0x'+deviceobject
            
        a=DeviceInfo(driverobject=info.get('DriverObject', '0'),  deviceobject=deviceobject, lowerdeviceobject=info.get('DriverObject', '0'), iotimer=info.get('Timer', '0'))
        return a
    except Exception, err:
        print err
        return None

if __name__=='__main__':
    pass

