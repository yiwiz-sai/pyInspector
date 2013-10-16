#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pefile
import pykd
from common import *

class ExportFuncInfo(object):
    def __init__(self, funcname='', modulename='', baseaddr=0, funcaddr=0, funcoffset=0, ordinal=-1, forwarder=''):
        super(ExportFuncInfo, self).__init__()
        self.funcaddr=funcaddr
        self.funcoffset=funcoffset
        if not funcname:
            self.funcname=''
        else:
            self.funcname=funcname
        self.modulename=modulename
        self.ordinal=ordinal
        self.forwarder=forwarder
        self.baseaddr=baseaddr
        pass

class ImportFuncInfo(object):
    def __init__(self, funcname='', sourcemodulename='', importmodulename='', iatoffset=0, ordinal=-1):
        super(ImportFuncInfo, self).__init__()
        self.iatoffset=iatoffset
        self.funcname=funcname
        self.sourcemodulename=sourcemodulename
        self.importmodulename=importmodulename
        self.ordinal=ordinal
        
def inspectIatEatHook(modulelist, eprocessaddr=None):
    try:
        if eprocessaddr:
            cmdline='.process /P /r %x' % eprocessaddr
            r=pykd.dbgCommand(cmdline)
            
        importfunctable=[]
        exportfunctable={}
        for mo in modulelist:
            modulepath=mo.filepath
            modulename=mo.name.lower()
            s=os.path.splitext(modulename)
            if len(s)>=2:
                modulebasename=s[0]
            else:
                modulebasename=modulename
 
            baseaddr=mo.baseaddr
            if not os.path.exists(modulepath):
                continue
            elif not baseaddr:
                continue
            filedata=open(modulepath, 'rb').read()
            pe = pefile.PE(data=filedata, fast_load=True)
            if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
                raise Exception("%s is not a pe file" % modulepath)

            pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'])
            if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
                exporttable=pe.DIRECTORY_ENTRY_EXPORT
                for i in exporttable.symbols:
                    funcoffset=pe.get_rva_from_offset(i.address_offset)
                    funcaddr=baseaddr+i.address
                    #print hex(baseaddr+funcoffset) ,hex(funcaddr)
                    info=ExportFuncInfo(i.name, modulename, baseaddr, funcaddr, funcoffset, i.ordinal, i.forwarder)
                    exportfunctable[funcaddr]=info

            pe.parse_data_directories(pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'])
            if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
                importtable=pe.DIRECTORY_ENTRY_IMPORT
                for importitem in importtable:
                    importname=importitem.dll
                    for i in importitem.imports:
                        #thunkvalue=i.bound
                        iatoffset=i.address-pe.OPTIONAL_HEADER.ImageBase+baseaddr
                        funcname=i.name
                        #print '%s %s %x %x %s' % (importname, funcname,  baseaddr, iatoffset, i.ordinal)
                        info=ImportFuncInfo(funcname, modulename, importname, iatoffset, i.ordinal)
                        importfunctable.append(info)
        

        #for info in exportfunctable.values():
        #    print info.funcname, hex(info.funcaddr)
        #return
        #print 'inspect EATHOOK'
        #inspect export table
        for info in exportfunctable.values():
            currentoffsetvalue=pykd.ptrDWord(info.funcoffset+info.baseaddr)
            sourceoffsetvalue=info.funcaddr-info.baseaddr
            if sourceoffsetvalue!=currentoffsetvalue:
                print 'EATHOOK:(%s!%s) baseaddr:%x offset:%x value:%x<->%x' % (info.modulename, info.funcname, info.baseaddr, info.funcoffset, sourceoffsetvalue, currentoffsetvalue)
        #print 'inspect IATHOOK'
        #inspect import table
        for i in importfunctable:
            currentfuncaddr=pykd.ptrPtr(i.iatoffset)
            if not exportfunctable.get(currentfuncaddr):
                hookfuncname=pykd.findSymbol(currentfuncaddr)
                if i.ordinal:
                    #by ordinal
                    print 'IATHOOK:(source:%s import:%s!%d)%x<->%x(%s)' % (i.sourcemodulename, i.importmodulename,i.ordinal,0 , currentfuncaddr, hookfuncname)
                else:
                    #by name
                    print 'IATHOOK:(source:%s import:%s!%s)%x<->%x(%s)' % (i.sourcemodulename, i.importmodulename,i.funcname, 0, currentfuncaddr, hookfuncname)

    except Exception, err:
        print traceback.format_exc()

  
from dll_op import *
def inspectAllRing3IatEatHook():
    processlist=listProcessByPsActiveProcessHead()
    for eprocessinfo in processlist:
        print '='*10, 'process:%x pid:%d %s' % (eprocessinfo.eprocessaddr, eprocessinfo.pid, eprocessinfo.filepath), '='*10
        modulelist=listModuleByVadRoot(eprocessinfo.eprocessaddr)
        if not modulelist:
            print 'the process has no modules(vadroot is null)'
        else:
            inspectIatEatHook(modulelist, eprocessinfo.eprocessaddr)
    print 
    print 'inspect completely'
    
def inspectProcessIatEatHook(eprocessaddr):
    modulelist=listModuleByVadRoot(eprocessaddr)
    if not modulelist:
        print 'the process has no modules(vadroot is null)'
    else:
        inspectIatEatHook(modulelist, eprocessaddr)
    print 
    print 'inspect completely'
    
from driver_op import *
def inspectDriverIatEatHook():
    driverlist=listDriverByPsLoadedModuleList()
    if not driverlist:
        print 'can not get driver list'
    else:
        inspectIatEatHook(driverlist)
    print 
    print 'inspect completely'
    
if __name__=='__main__':
    if sys.argv[1]=='allring3':
        inspectAllRing3IatEatHook()
    elif sys.argv[1]=='allring0':
        inspectDriverIatEatHook()
    elif sys.argv[1]=='ring3':
        eprocessaddr=int(sys.argv[2], 16)
        eprocessobj=pykd.typedVar('nt!_EPROCESS', eprocessaddr) 
        eprocessinfo=ProcessInfo()
        if eprocessinfo.init(eprocessobj):
            print '='*10, 'process:%x pid:%d %s' % (eprocessinfo.eprocessaddr, eprocessinfo.pid, eprocessinfo.filepath), '='*10
            inspectProcessIatEatHook(eprocessaddr)
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
