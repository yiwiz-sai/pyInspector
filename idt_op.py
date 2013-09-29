#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
import windbgCmdHelper
def listIDT():
    idt_symbol_table={}
    try:
        for cpuidx in xrange(windbgCmdHelper.g_cpunumber):
            print '='*20
            cmdline='!pcr %d' % cpuidx
            r=pykd.dbgCommand(cmdline) 
            r=r.splitlines()
            for i in r:
                i=i.strip()
                if i.startswith('IDT'):
                    idtaddr=i.split(':')[1].strip()
                    print 'cpu %d idtaddr:%s' % (cpuidx, idtaddr)
                    r2=pykd.dbgCommand('dds %s L200' % idtaddr)
                    r2=r2.splitlines()
                    j=0
                    idx=0
                    while j<len(r2):
                        a=r2[j].strip().split(' ')[2]
                        b=r2[j+1].strip().split(' ')[2]
                        low=a[4:]
                        high=b[0:4]
                        interrupt_addr=high+low
                        if interrupt_addr in idt_symbol_table:
                            print '%02d' % idx, interrupt_addr, idt_symbol_table[interrupt_addr]
                        elif interrupt_addr=='0':
                            print '%02d' % idx, interrupt_addr
                        else:
                            r3=windbgCmdHelper.ln('ln %s' % interrupt_addr)
                            if r3[0]=='':
                                print '%02d' % idx, interrupt_addr
                            else:
                                name=r3[0].strip().split(' ')[-1]
                                print '%02d' % idx, interrupt_addr, name
                                idt_symbol_table[interrupt_addr]=name
                        j+=2
                        idx+=1
            
    except Exception, err:
        print err
        
if __name__=='__main__':
    listIDT()
    pass
