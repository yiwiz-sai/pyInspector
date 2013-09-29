#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
class DriverInfo(object):
    def __init__(self, name='', filepath='', driverobject=0,  baseaddr=0, modulesize=0, deviceobjectlist=[], dispatchfuncs=[], fastiofuncs=[]):
        self.name=name.lower()
        self.filepath=filepath.lower()
        self.baseaddr=baseaddr
        self.driverobject=driverobject
        self.modulesize=modulesize
        self.deviceobjectlist=deviceobjectlist
        self.dispatchfuncs=dispatchfuncs
        self.fastiofuncs=fastiofuncs
        
class DeviceInfo(object):
    def __init__(self, driverobject=0, deviceobject=0,  lowerdeviceobject=0, iotimer=0):
        self.driverobject=driverobject
        self.deviceobject=deviceobject
        self.lowerdeviceobject=lowerdeviceobject
        self.iotimer=iotimer

class ModuleInfo(object):
    pass
    
class ProcessInfo(object):
    def __init__(self, eprocess=0, pid=0 ,  parentpid=0, name='', fullpath='', peb=0):
        self.eprocess=eprocess
        self.pid=pid
        self.parentpid=parentpid
        self.name=name
        self.fullpath=fullpath
        self.peb=peb

class ThreadInfo(object):
    def __init__(self, driverobject=0, deviceobject=0,  lowerdeviceobject=0, iotimer=0):
        pass


if __name__=='__main__':
    pass

