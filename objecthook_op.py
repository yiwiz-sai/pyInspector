#!/usr/bin/env python
# -*- coding: utf-8 -*
# author: SAI
import os,sys,time
import traceback
import pykd
from common import *

def listObjectCallback():
    try:
        cmdline='!object \objecttypes'
        r=pykd.dbgCommand(cmdline)
        featurestr='----\n'
        pos=r.find(featurestr)
        if pos==-1:
            return
        r=r[pos+len(featurestr):].splitlines()
        for i in r:
            if i.find('Type'):
                typeobjectaddr, name=i.split(' Type ')
                pos=typeobjectaddr.rfind(' ')
                if pos==-1:
                    return
                name=name.strip()
                typeobjectaddr=typeobjectaddr[pos+1:]
                typeobjectaddr=int(typeobjectaddr, 16)
                print '-'*20
                print 'typeobject "%s":%x' % (name, typeobjectaddr)
                typeobject=pykd.typedVar('nt!_OBJECT_TYPE', typeobjectaddr) 
                TypeInfo=pykd.typedVar('nt!_OBJECT_TYPE_INITIALIZER', typeobject.TypeInfo)
                for membername, membervalue in TypeInfo:
                    if membername.endswith('Procedure'):
                        funcaddr=int(membervalue)
                        if funcaddr:
                            symbolname=pykd.findSymbol(funcaddr)
                        else:
                            symbolname=''
                        print '%s %x %s' % (membername, funcaddr, symbolname)
                        
    except Exception, err:
        print traceback.format_exc()
        
if __name__=='__main__':
    listKernelNotify()
    pass
