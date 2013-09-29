#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pykd
import windbgCmdHelper
from struct_info import *

def listProcessByListEntry(eprocess_table,  cmdline):
    try:
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        p=None
        for i in r:
            i=i.strip()
            if i=='':
                continue
            if i.startswith('+'):
                if p:
                    name, data=i.split(':')
                    data=data.strip()
                    name=name.strip().split(' ')[-1]
                    if name=='UniqueProcessId':
                        p.pid=int(data.split(' ')[0], 16)
                    elif name=='InheritedFromUniqueProcessId':
                        if data=='(null)':
                            p.parentpid=0
                        else:
                            p.parentpid=int(data.split(' ')[0], 16)
                    elif name=='ImageFileName':
                        pos=data.find('"')
                        if pos!=-1:
                            p.name=data[pos:].strip('"')
            else:
                eprocess=i.split(' ')[0]
                if eprocess not in eprocess_table:
                    p=eprocess_table[eprocess]=ProcessInfo(eprocess=int(eprocess, 16))
                else:
                    p=eprocess_table[eprocess]
                    
    except Exception, err:
        print err


def listProcessByPsActiveProcessHead(eprocess_table={}):
    cmdline='''!list \"-t nt!_LIST_ENTRY.Flink -x \\"r $t1=@@(#CONTAINING_RECORD(@$extret, nt!_EPROCESS, ActiveProcessLinks));da $t1;dt nt!_EPROCESS UniqueProcessId InheritedFromUniqueProcessId Vm.VmWorkingSetList SessionProcessLinks ImageFileName Pcb.ReadyListHead Pcb.ThreadListHead @$t1\\" poi(nt!PsActiveProcessHead)\" '''
    list_process_by_list_entry(eprocess_table, cmdline)

def listProcessByPspcidTable(eprocess_table={}):
    try:
        cmdline='!process 0 0'
        r=pykd.dbgCommand(cmdline)
        r=r.splitlines()
        p=None
        for i in r:
            i=i.strip()
            if i.startswith('PROCESS'):
                members=i.strip().split('  ')
                eprocess=members[0].split(' ')[1]
                if eprocess not in eprocess_table:
                    p=eprocess_table[eprocess]=ProcessInfo(eprocess=int(eprocess, 16))
                else:
                    p=eprocess_table[eprocess]
                
                for j in members[1:]:
                    j=j.split(':')
                    if j==[]:
                        continue
                    name=j[0].strip()
                    if name=='Cid':
                        data=j[1].strip()
                        p.pid=int(data, 16)
                    elif name=='ParentCid':
                        data=j[1].strip()
                        p.parentpid=int(data, 16)
                    elif name=='Peb':
                        data=j[1].strip()
                        p.peb=int(data, 16)
                        
            elif i.startswith('DirBase'):
                continue
            
            elif i.startswith('Image'):
                p.name=i.split(':')[1].strip()
        
    except Exception, err:
        print err
    
def listProcess():
    eprocess_table={}
    listProcessByPspcidTable(eprocess_table)
    print 'eprocess pid ppid peb name fullpath'
    for i in eprocess_table.values():
        print '%x %5d %5d %x %s %s' % (i.eprocess, i.pid, i.parentpid, i.peb, i.name, i.fullpath)
        
if __name__=='__main__':
    listProcess()
    pass
