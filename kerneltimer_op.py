#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *
mmhighestuseraddress=pykd.ptrPtr(pykd.getOffset('nt!MmHighestUserAddress'))

def inspectKernelTimer():
    try:
        cmdline='.reload;'
        r=pykd.dbgCommand(cmdline)
        cmdline=r'!timer'
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        start=0
        idx=0
        for i in r:   
            i=i.strip() 
            if i.startswith('List Timer'):
                start=1
                continue
            
            if start!=1:
                continue
            
            data=i.strip()
            pos=data.find('(DPC @ ')
            if pos!=-1:
                endpos=data.find(')', pos)
                data=data[pos+len('(DPC @ '):endpos]
                dpc=pykd.addr64(int(data, 16))
                if dpc<=int(mmhighestuseraddress):
                    print i, '!!!!!!!!'
                else:
                    dpcobj=pykd.typedVar('nt!_KDPC', dpc)
                    symbolname=pykd.findSymbol(dpcobj.DeferredRoutine)
                    print '%d dpc:%x timerfunc:%x %s' % (idx, int(dpc), int(dpcobj.DeferredRoutine), symbolname)
                idx+=1
    except Exception, err:
        print traceback.format_exc()     
    
if __name__=='__main__':
    inspectKernelTimer()
    pass

