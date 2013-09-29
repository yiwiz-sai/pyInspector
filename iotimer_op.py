#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import windbgCmdHelper
import directory_op
import device_op
from struct_info import *

def listIOTimer(devices={}):
    def listIOTimerCallback(obj, type, param):
        if type=='Device':
            if obj not in devices:
                devices[obj]=device_op.getDeviceInfo(obj)
        return True
    
    directory_op.crawl_object_by_directory('\\', listIOTimerCallback, devices)
    for obj in devices.values():
        if obj.iotimer!='0':
            print obj.deviceobject, obj.iotimer
    
if __name__=='__main__':
    starttime=time.time()
    checkIOTimer()
    print time.time()-starttime
