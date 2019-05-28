#!/usr/bin/env python3

"""
Based on the tracemac in mnetsuite, an SNMP and CDP based
tracerouter from REDACTED made for the REDACTED network
"""
__author__ = 'Michael Belousov'

import sys
from argparse import ArgumentParser
import easysnmp
import validators
from textwrap import dedent
# TODO: use IPAddress.bin,.packed, etc for translation
from netaddr import IPAddress, EUI, mac_unix
from netaddr.core import AddrFormatError

class Mac(EUI):
    """A netaddr.EUI subclass that can be constructed 
    from octet streams"""
    def __init__(self, pat):
        try:
            super().__init__(
                    ''.join(
                        (hex(ord(c))[2:] for c in pat)))
        except AddrFormatError:
            super().__init__(pat)
        self.dialect = mac_unix

def printmul(*args):
    """print dedented multiline python strings"""
    print(*(dedent(a) for a in args), end='')

# see bridge-MIB

# management specific 
OID_MGMT_STATICTABLE        = '.1.3.6.1.2.1.17.5.1'

# OID for VLAN states
OID_vtpVlanState            = '1.3.6.1.4.1.9.9.46.1.3.1.1.2'
# OID for VLAN's CAM table (requires indexed community
OID_dot1dTpFdbAddress       = '1.3.6.1.2.1.17.4.3.1.1'
# OID for vlan bridge port number
OID_dot1dTpFdbPort          = '1.3.6.1.2.1.17.4.3.1.2'
# OID for bridge port to idindex mapping
OID_dot1dBasePortIfIndex    = '1.3.6.1.2.1.17.4.3.1.2'
# OID for ifName for correlation
OID_ifName                  = '1.3.6.1.2.1.31.1.1.1.1'

OID_SYSNAME	                = '1.3.6.1.2.1.1.5.0'
OID_VLANS	                = '1.3.6.1.4.1.9.9.46.1.3.1.1'
OID_VLAN_CAM	            = '1.3.6.1.2.1.17.4.3.1.1'
OID_BRIDGE_PORTNUMS         = '1.3.6.1.2.1.17.4.3.1.2'
OID_IFINDEX	                = '1.3.6.1.2.1.17.1.4.1.2'
OID_IFNAME	                = '1.3.6.1.2.1.31.1.1.1.1'	      # + ifidx (BULK)
OID_CDP	                    = '1.3.6.1.4.1.9.9.23.1.2.1.1'
OID_CDP_IPADDR	            = '1.3.6.1.4.1.9.9.23.1.2.1.1.4'
OID_CDP_DEVID	            = '1.3.6.1.4.1.9.9.23.1.2.1.1.6'
"""SNMP OIDs"""

community = None
"""SNMP community string"""

root = 'REDACTED'
rootip = 'REDACTED'
"""default root and ip"""

default_snmp = {
        'hostname'  : root,
        'community' : community,
        'version'   : 2
    }

def snmp_get(*oids, **sessargs):
    """snmp get some OID values from a target"""
    sessargs = {**default_snmp, **sessargs}
    return easysnmp.snmp_get(*oids, **sessargs)

# NOTE: if performance is needed, could return 
# an @functools.lru_cached function for access
def snmp_walk(*oids, **sessargs):
    """snmp walk a host for an oid"""
    if not oids:
        oids = ['.1.3.6.1.2.1']
    sessargs = {**default_snmp, **sessargs}
    return easysnmp.snmp_walk(*oids, **sessargs)

def indexedcommunity(vlan):
    """return a vlan's subcommunity"""
    return f'{community}@{vlan}'

def makeoid(*args):
    """
    make an OID variable arguments, including iterator
    arguments which are flattened by a single depth
    """
    for i, a in enumerate(args):
        if (not isinstance(a, str) 
                and hasattr(a, '__iter__')):
            args = args[:i] + tuple(a) + args[i+1:]
    return '.'.join((str(a) for a in args))

# TODO: replace with versatile data type?
def splitoid(oid):
    return [o for o in oid.split('.') if o]

# TODO: switch to using netaddr for ip
def octet_to_ip(ip):
    """get ip from octet stream"""
    if not ip:
        return ip
    ip = int(ip, 0)
    ip = (f'{ip >> 24 & 0xff}.{ip >> 16 & 0xff}.'
            f'{ip >> 8 & 0xff }.{ip & 0xff}')
    '.'.join((ord(c) for c in ip))
    return ip

def octet_to_mac(mac):
    """get mac from octet stream"""
    return ':'.join(
            (hex(ord(c))[2:].zfill(2) for c in mac))

def hop(ip, target, pathref):
    # add host data to path
    sysname = snmp_get(OID_SYSNAME, hostname=ip)
    pathref.append(sysname)
    # add checking of cycles?
    print(f'{sysname} ({ip})')
    # search get enabled VLAN indexes
    vlantable = snmp_walk(OID_vtpVlanState, hostname=ip)
    def vlanfilt(vlantable):
        for v in vlantable:
            v = int(splitoid(v.oid)[-1])
            if v < 1002:
                yield v
    for vlan in vlanfilt(vlantable):

        vcommunity = indexedcommunity(vlan)

        # search CAM table for target
        camtable = snmp_walk(OID_dot1dTpFdbAddress, 
                hostname=ip,
                community=vcommunity)

        mac = [c for c in camtable if c.value == target]

        if mac:
            
            mac, = mac

            # bridge port number
            # bridgeport = snmp.get_val(
            #       OID_BRIDGE_PORTNUMS + makeoid(p[11:17]))
            bridgeports = snmp_walk(OID_dot1dTpFdbPort,
                    hostname=ip,
                    community=vcommunity)

            bridgeport, = (b for b in bridgeports 
                    if b.oid == match.oid)

            # interface index
            ifidx = snmp_walk(makeoid(OID_ifIndex), 
                    community=vcommunity)
            # bridge port to ifIndex mapping
            ifindexes = snmp_walk(OID_dot1dBasePortIfIndex,
                    hostname=ip,
                    community=vcommunity)

            index, = (i for i in ifindexes 
                    if i.oid == bridgeport.oid)

            # interface port
            ports = snmp_walk(OID_ifName, hostname=ip)

            # XXX I just added this since the {port} isn't defined below
            port = ports[0]

            printmult(f"""\
                    VLAN: {vlan}
                    Port: {port}
                    """)

            # get CDP neighbors
            # XXX: this shouldn't work, no snmp identifier
            cdptable = snmp.get_bulk(OID_CDP, hostname=ip)
            # quick filter generator
            def cdpfilt(itr):
                for cdpn, cdpv in itr:
                    if str(cdpn).startswith(OID_CDP_DEVID):
                        yield cdpn, cdpv
            for cdprow in cdptable:
                for cdpn, cdpv in cdpfilt(cdprow):
                    # skip if this row isn't a CDP_DEVID
                    cdpn = cdpn.split('.')
                    # skip row if id isn't correct # XXX
                    if ifidx != cdpn[14]:
                        continue
                    # XXX: this shouldn't work, no snmp identifier
                    # get remote IP
                    remip = snmp.look_up(cdptable, 
                            makeoid(OID_CDP_IPADDR, 
                                ifidx, 
                                cdpn[15]))
                    printmul(f"""\
                    Next Node: {str(cdpv)}
                    Next IP: {remip}
                    """)
                    return rip
    print('MAC not found')


def run(target):
    """run the full trace"""
    ip = rootip
    path = []
    printmul(f"""\
    target MAC: {target}
    root: {root}

    Start
    """)
    while(ip):
        ip = hop(ip, target, path)
        print('---')
    print('Done')


if __name__ == '__main__':
    parser = ArgumentParser(description="Trace REDACTED stuff")
    parser.add_argument('-c', '--community', 
            help='SNMP community', 
            default='public')
    parser.add_argument('target', 
            help='target MAC address')
    args = parser.parse_args()

    validators.mac_address(args.target)

    # TODO: use getpass module or *.ini 
    # for acquiring community
    community = args.community

    run(args.target)
