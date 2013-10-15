#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pefile
import pykd
from common import *

class FuncInfo(object):
    def __init__(self, funcname='', dllname='', funcaddr=0, ordinal=-1, forwarder=''):
        self.funcaddr=funcaddr
        self.funcname=funcname
        self.dllname=dllname
        self.ordinal=ordinal
        self.forwarder=forwarder
        
def checkRing3Hook(eprocessaddr,processpath, loadmodules=[]):
    try:
        symbolpath=g_sympath+';'+os.path.abspath(os.path.dirname(processpath))
        if eprocessaddr:
            cmdline='.process /P %x;.sympath %s;' % (eprocessaddr, symbolpath)
            r=pykd.dbgCommand(cmdline)
        cmdline='.reload;'
        r=pykd.dbgCommand(cmdline)
        
        for mo in loadmodules:
            modulepath=mo.dllpath
            if os.path.exists(modulepath):
                filedata=open(modulepath, 'rb').read()
                pe = pefile.PE(data=filedata, fast_load=True)
                if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
                    raise Exception("%s is not a pe file" % modulepath)
 
                pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'])
                exporttable=pe.DIRECTORY_ENTRY_EXPORT
                if exporttable==0:
                    continue
                
                #export=pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'])
                #pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'])
                #for i in pe.DIRECTORY_ENTRY_IMPORT:
                #    print '-'*10+i.dll+'-'*10
                    #if i.dll not in loadmodules:
                    #    loadmodules[i.dll]=
                #    for j in i.imports:
                #        print j.ordinal, j.name

    except Exception, err:
        print traceback.format_exc()

if __name__=='__main__':
    from dll_op import *
    from process_op import *
    #eprocessinfo=find_eprocess('calc.exe')
    eprocessaddr=0x893cd020  
    fullpath='c:\\windows\\system32\\kernel32.dll'#eprocessinfo.fullpath
    if eprocessaddr:
        loadmodules=getModules(eprocessaddr)
        if loadmodules:
            checkRing3Hook(eprocessaddr, fullpath, loadmodules)
    pass

'''    
try:
    memdata=''
    cmdline='db %x %x' % (memoffsetstart, memoffsetend-1)
    r=pykd.dbgCommand(cmdline)
    r=r.splitlines()
    for i in r:
        r=i.strip().split('  ')[1].split(' ')
        for j in r:
            for a in j.split('-'):
                memdata+=a
    #memdata=binascii.a2b_hex(memdata)
    rawdata=filedata[fileoffsetstart:fileoffsetend]
    print binascii.b2a_hex(rawdata)[0:10]
    print memdata[0:10]
    #if memdata!=rawdata:
    #    print 'fuck'
    #else:
     #   print 'ok'
    #print len(memdata), len(memdata2), len(rawdata)
except Exception, err:
    print err
'''
