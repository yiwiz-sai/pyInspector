#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

def crawl_object_by_directory(callback, param, dirname='\\'):
    cmdline='!object '+dirname
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

        if not callback(obj, type, param):
            return False
            
        if type=='Directory':
            childname=dirname+name+'\\'
            if not crawl_object_by_directory(callback, param, childname):
                return False
                
    return True
    
if __name__=='__main__':
    pass

