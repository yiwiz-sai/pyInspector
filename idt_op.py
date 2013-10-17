#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
from common import  *

def listIDT():
    idt_symbol_table={}
    try:
        for cpuidx in xrange(g_cpunumber):
            print '='*20
            cmdline='!pcr %d' % cpuidx
            r=pykd.dbgCommand(cmdline) 
            r=r.splitlines()
            for i in r:
                i=i.strip()
                if i.startswith('IDT'):
                    idtaddr=i.split(':')[1].strip()
                    #interrupts=pykd.loadPtrs(int(idtaddr, 16), 256)
                    print 'cpu %d idtaddr:%s' % (cpuidx, idtaddr)
    except Exception, err:
        print err

if __name__=='__main__':
    print 'no support'
