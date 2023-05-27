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
    
    def processRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        sAMAccountName = ''
 
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'sAMAccountName':
                    if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                        # User Account
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error('Skipping item, cannot process due to error %s' % str(e))
            pass

    def connectLdap(self):
        if self.__kdcHost is not None:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__domain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                            self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                    "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                        "must match exactly each other.")
                raise
        self.__ldapConn = ldapConnection
    
    def getUsernameFromSid(self, sid):            
        searchFilter = "(&(objectSid=%s))" % sid

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)
            resp = self.__ldapConn.search(searchFilter=searchFilter,
                                attributes=['sAMAccountName','memberOf'],
                                sizeLimit=0, searchControls = [sc])

            #print(resp)
        except ldap.LDAPSearchError:
                raise

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            userAccountControl = 0
            delegation = ''
            objectType = ''
            rightsTo = []
            protocolTransition = 0
            ret = {}
            #after receiving responses we parse through to determine the type of delegation configured on each object
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # User Account
                            ret['name'] = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'memberOf':
                        for x in attribute['vals']:
                            ret['group'] = attribute['vals']
            
                return ret        

            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass




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
                print("[+] Username: %s" % self.getUsernameFromSid(sid)['name'])
                print("[+] User Groups:")
                for x in self.getUsernameFromSid(sid)['group']:
                    print('\t\t' + x)

        self.__ldapConn.close()
        dce.disconnect()


# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)
    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                          'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                          'again with -codec and the corresponding codec ' % CODEC)

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. '
                                         'If omitted it will use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab (options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    taskenum = TSCH_ENUM(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip)
    taskenum.play(address)
