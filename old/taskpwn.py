#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script enumerates scheduled tasks and grabs the user and their groups.
#
# Author:
#   Josh B (@0xjbb)

from __future__ import division
from __future__ import print_function
import string
import sys
import argparse
import time
import random
import logging

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, \
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from impacket.ldap import ldap, ldapasn1
from six import PY2

CODEC = sys.stdout.encoding

class TSCH_ENUM:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, dc_ip=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__kdcIP = dc_ip

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        try:
            self.doStuff(rpctransport)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >=0:
                logging.info('When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work')

    def doStuff(self, rpctransport):
        # Might not be pretty, but it do work. 
        def getXMLTag(s, split):
            a = s.split("</%s>" % split)
            return a[0].split("<%s>" % split)[1]

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        if self.__doKerberos is True:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(tsch.MSRPC_UUID_TSCHS)
        
        request = tsch.SchRpcEnumTasks()
        request['path'] = '\\\x00'
        request['flags'] = tsch.TASK_ENUM_HIDDEN
        request['startIndex'] = 0
        request['cRequested'] = 10
        resp = dce.request(request)
        self.connectLdap()

        for x in resp['pNames']:
            resp = tsch.hSchRpcRetrieveTask(dce, '\\%s' % x['Data'])
            taskname = x['Data']
            sid = getXMLTag(resp['pXml'], "UserId")

            if sid.startswith("S-1-5-21"):
                cmd = getXMLTag(resp['pXml'], "Command")
                print("[+] Target: %s" % self.__target)
                print("[+] Taskname: %s" % taskname)
                print("[+] Command: %s" % cmd)
                #print("[+] Username: %s" % self.getUsernameFromSid(sid)['name'])
                print("[+] User Groups:")
                for x in self.getUsernameFromSid(sid)['group']:
                    print('\t\t' + x)

        self.__ldapConn.close()
        dce.disconnect()
