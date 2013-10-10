#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
from common import *

g_regkey_map=\
{
    
}
def listReg(regpath='System\CurrentControlSet\Services\Tcpip!*'):
    try:
        cmdline='!dreg %s' % regpath
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        for i in r:
            print i
    except Exception, err:
        print err
        
if __name__=='__main__':
    listReg()
    pass

