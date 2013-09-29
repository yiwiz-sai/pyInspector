#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
import windbgCmdHelper
def listKernelTimer():
    l=[]
    try:
        cmdline=r'!timer'
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        start=0
        for i in r:   
            i=i.strip() 
            if i.startswith('List Timer'):
                start=1
                continue
            
            if start!=1:
                continue
            
            if i.find(']')!=-1:
                data=i.split(']')[1][1:]
                data=data.strip()
                print data
                l.append(data)
        
        return l
    except Exception, err:
        print err
        return []
        
if __name__=='__main__':
    listKernelTimer()
    pass

