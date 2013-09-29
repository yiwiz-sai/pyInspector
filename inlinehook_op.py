#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import pefile
import pykd
import windbgCmdHelper
import binascii
def checkInlineHook(modulepath=windbgCmdHelper.g_kernelpath, baseaddr=windbgCmdHelper.g_kernelbase, modulesize=windbgCmdHelper.g_kernelsize):
    try:
        symbolpath=os.path.abspath(os.path.dirname(modulepath))
        cmdline='.reload %s;.sympath %s' % (os.path.basename(modulepath), symbolpath)
        r=pykd.dbgCommand(cmdline)
                
        filedata=open(modulepath, 'rb').read()
        pe = pefile.PE(data=filedata, fast_load=True)
        if pe.DOS_HEADER.e_magic!=0X5A4D or pe.NT_HEADERS.Signature!=0x4550:
            raise Exception("%s is not a pe file" % modulepath)
        for i in pe.sections:
            try:
                if pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_DISCARDABLE']&i.Characteristics:
                    #print i.Name, 'discard'
                    continue
                elif not (pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']&i.Characteristics):
                    #print i.Name, 'not executable'
                    continue
                
                comparesize=i.Misc_VirtualSize
                fileoffsetstart=i.PointerToRawData
                fileoffsetend=fileoffsetstart+comparesize
                memoffsetstart=baseaddr+ i.VirtualAddress
                memoffsetend=memoffsetstart+comparesize
                print '='*20
                print '%s :%x %x <--> %x %x  size:%d' % (i.Name, fileoffsetstart, fileoffsetend, memoffsetstart, memoffsetend, comparesize)
                cmdline='!chkimg nt -r %x %x -v -d' % (memoffsetstart, memoffsetend)
                r=pykd.dbgCommand(cmdline)
                if r.find('0 errors')!=-1:
                    print 'no hooks'
                else:
                    r=r.splitlines()
                    for i in r:
                        print i
                    
            except Exception, err:
                print err
     
    except Exception, err:
        print err
    
if __name__=='__main__':
    checkInlineHook()
    pass


'''    try:
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
                print err'''
