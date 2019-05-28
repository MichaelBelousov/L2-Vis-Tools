#!/usr/bin/python3
# must be run as root for nmap
"""
A script that runs nmap against the ip network currently specified in the
file, 'private/REDACTED.ips'.
For hosts of varying visibility, it may use multiple scans for a performance
boost. 
It must be run as root for some of the nmap functionality. 
(not if running with the '--no-scan' option)

argparse also provides a good list of the implemented arguments and their uses.

OPTIONS
    -h
        help
    -n/--no-scan
        do not perform an nmap scan, instead just generate the 
        aggregated data from previously gathered nmap data.
    -d/--discard-log
    this is out of date and will remain so for now. Use the -h command to see a more up to date
    documentation of the command line functionality

TODO
    ? add a more verbose output option that preserves most nmap host data?
    - clean up naming consistency
    - check for IP syntax errors while reading *.ips
    ? add caching of traceroute data for individual hosts
        ? using database schema? pickled table?
    - add unit test battery?
    - speedup scan processing
    COMMAND LINE:
        - add specifying the *.ips file

OTHER
    The current nmap scan performed is equivalent to:
    nmap -v -sn -Pn -T5 --traceroute -oX <nmapresultpath> -iL <hostslistfile>
"""

import subprocess as subproc
from netaddr import IPNetwork, iprange_to_cidrs, IPAddress
import os
import sys
from os import path
from xmltodict import parse as xmlparse, unparse as xmldump
from collections import OrderedDict as odict
from securitycenter import SecurityCenter5
from configparser import SafeConfigParser
import tempfile
import argparse
from collections import OrderedDict as odict

#### Module-Level [Default] Attributes

root_dir = os.curdir
"""
directory root for files created and used by trace.py.
can have potentially confidential information.
"""

targetfile = path.join(root_dir, 'REDACTED.ips') 
"""file which the IPlist object is initiated with, 
and holds all the IPs to be scanned"""

nmapxmlpath = path.join(root_dir, 'nmap_log.xml')
"""path to nmap scan log"""

resultpath = path.join(root_dir, 'trace.xml')
"""path of generated xml file"""

hostspath = tempfile.mkstemp(prefix='.temp_hostpath')[1]
"""temporary file that is used to list the hosts for nmap to scan"""

# TODO: rename to something like listtags
xmlforced = ('host', 'hop', 'network')  #, 'address')
"""tuple of xml tags that form lists, especially for use with xmltodict"""

#### End Module-Level Attributes

def iprange_decode(ipr):
    """
    Returns an ip list from a subnet or range
    """
    # netaddr module should have robust enough AddrFormatError for this
    result = []
    if '-' in ipr:
        ips = ipr.split('-')
        ips = iprange_to_cidrs(*ips)
        for cidr in ips:
            result += cidr
    else:
        result += IPNetwork(ipr)
    result = [str(i) for i in result]
    return result

# TODO: rename, it's just a host iterator/network mapping now
# TODO: add support for domain names
# TODO: add support for miscellaneous IPs
# TODO: use IPSet from netaddr
class IPFile(odict):
    """
    On instantiation, fetches asset data on init, and maps ips
    to networks defined in the file.
    Can also parses an *.ips file, which is in the format:
    Networkname: iprange,CIDR,singleip,etc,e.g.,10.9.40.1-10.9.40.4,137.99.22.231/30
    """
    # TODO: make alternative constructor/factory class method
    # @classmethod
    def fromstr(self, string):
        # TODO: add exceptions for file syntax errors
        lines = string.split('\n')
        lines = [l.strip() for l in lines]
        lines = [l for l in lines if not l.startswith('#') and l]
        lines.sort()
        for line in lines:
            if ':' in line:
                line = line.split(':')
                sect = line[0].strip()
                ips = line[1].strip()
                ips = ips.split(',')
                ips = [i.strip() for i in ips]
                ranges = [i for i in ips for i in iprange_decode(i)]
                for ip in ranges:
                    self[ip] = sect
            else:  # TODO: consider
                self[line] = 'Misc'
    # @classmethod
    def fromfile(self, filename):
        """extract IPs from *.ips file"""
        with open(filename) as f:
            string = f.read()
            self.fromstr(string)
    def fromnmapxml(self, filename):
        """extract IPs from nmap xml scan log"""
        nmapxml = xmlparse(open(filename).read(), force_list=xmlforced)
        if 'host' not in nmapxml['nmaprun']:
            raise Exception('No hosts scanned\n{}\n'.format(hostspath))
        for host in nmapxml['nmaprun']['host']:
            if isinstance(host['address'], list):
                host['address'] = host['address'][0]
            addr = host['address']['@addr']  # XXX: ensure ipv4 addr
            # print(addr, type(addr))
            self[addr] = 'Miscellaneous'  # TODO: add global/config setting

def parse_result(output=sys.stdout):
    print('Parsing nmap results if they exist from scan...')
    try:
        nmapxml = xmlparse(open(nmapxmlpath, 'rb'), force_list=xmlforced)
    except FileNotFoundError as e:
        print('The results of the scan do not exist or have been moved!')
        raise
    scans = (nmapxml,)  #, nmapxml2)

    newxml = odict()
    newxml['networks'] = odict()
    newxml['networks']['network'] = []

    # extract and aggregate data from scans
    # TODO: remove terrible naming (referring to previous var)
    for nmapxml in scans:
        for network in sorted(list(set(iplist.values()))):
            # TODO: custom exception class
            if 'host' not in nmapxml['nmaprun']:
                raise Exception('No hosts scanned\n{}\n{}\n'.format(nmapxml, hostspath))
            for host in nmapxml['nmaprun']['host']:  # XXX: isolate ipv4 address directly
                if isinstance(host['address'], list):
                    host['address'] = host['address'][0]
            hosts = (n for n in nmapxml['nmaprun']['host'] if 
                iplist[n['address']['@addr']] == network)
            nethosts = odict()
            newxml['networks']['network'].append(nethosts)
            nethosts['networkname'] = network
            nethosts['hosts'] = odict()
            nethosts['hosts']['host'] = []
            for host in hosts:
                # do all the nasty xml creation
                # if you're unfamiliar with the '@keys' convention, 
                # odict use and etc, you should read the xmltodict 
                # module docs
                newhost = odict()
                newhost['address'] = host['address']['@addr']
                # in case hostnames is set to none or the tag doesn't even exist
                if host.get('hostnames') is not None:
                    newhost['hostname'] = host['hostnames']['hostname']['@name']
                else:
                    newhost['hostname'] = host['address']['@addr']
                # newhost['networkname'] = iplist[host['address']['@addr']]
                newhost['trace'] = odict()
                newhost['trace']['hop'] = []
                traceblob = []
                try:
                    for hop in host['trace']['hop']:
                        # TODO: Add a black hole for unknown trace nodes if possible
                        newhop = odict()
                        newhop['index'] = hop['@ttl']
                        # in case hostname is set to none or the tag doesn't even exist
                        if hop.get('@host') is None:
                            newhop['hostname'] = hop['@ipaddr']
                        else:
                            newhop['hostname'] = hop.get('@host')
                        newhop['address'] = hop['@ipaddr']
                        newhost['trace']['hop'].append(newhop)
                        traceblob.append( (newhop['index'], 
                                        newhop['hostname'] if newhop['hostname'] is not None else '',
                                        newhop['address']) )
                except KeyError as e:
                    if str(e) == 'trace':
                        raise Exception("It's likely that no traces were run, please inspect the nmap output")
                newhost['traceblob'] = str(traceblob)
                nethosts['hosts']['host'].append(newhost)
                # sort
                nethosts['hosts']['host'].sort(
                        key=lambda t:(t['hostname'] if t['hostname'] is not None else '', 
                        t.get('address', '')))
    xmldump(newxml, output, pretty=True)

# TODO: add proper output and parameters instead of iplist
# it's better to rely on parameters than some global scope object,
# more predictable, etc
def trace():
    """Runs nmap over hosts, then generates XML data from the result."""
    print('Running nmap scan(s) over network(s) in iplists object')
    # prepare hosts file for nmap
    with open(hostspath, 'w') as hostsfile:
        for ip in iplist:
            hostsfile.write('{}\n'.format(ip))

    # perform nmap scan
    args = ['nmap', '--privileged', '-sn', '-Pn', '-T5', '--traceroute', 
            '-v', '-oX', nmapxmlpath, '-iL', hostspath]
    try:
        subproc.check_output(args)  # replace with run in py>=3.5
    except subproc.CalledProcessError as e:
        print('Nmap failed to run')
        print(e.output)
        raise
    os.remove(hostspath)

# TODO: unconfuse the parameter names from cli args
def run(do_scan=True, keep_logs=False, output=sys.stdout):
    if do_scan:
        trace()
    parse_result(output)
    if not keep_logs and do_scan:
        os.remove(nmapxmlpath)

iplist = IPFile()
"""IPFile instance"""

if __name__ == '__main__':
    # command line arg setup
    p = argparse.ArgumentParser(
        description='A script that traces L2 data, see docstrings')
    # TODO: give this a file argument for an nmap XML log
    p.add_argument('-n', '--no-scan', default=None,
                    help='do not perform a new nmap scan')
    p.add_argument('-d', '--discard-log',
                    help="do not keep nmap's scan logs after tracing",
                    action='store_false')
    p.add_argument('-f', '--hostsfile', default=None,
                    help='file from which to read the ip groups to scan')
    # TODO prevent overwrites
    p.add_argument('-o', '--output', default=sys.stdout,
                    help='file to write results to, this currently overwrites')
    p.add_argument('-N', '--network-name', default='Misc',
                    help='name of the network for commandline argument IPs')
    p.add_argument('IPs', metavar='IP', type=str, nargs='*',
                    help='IPs to scan')
    args = p.parse_args()

    # TODO: detect when multiple hosts are specificed in different networks 
    # (they should be a part of both?... this might require duplicates in the xml structure)
    # TODO: allow read from stdin
    targets = ''
    if args.hostsfile is not None:
        targets += open(args.hostsfile, 'r').read()
    if args.IPs:
        targets += '\n{}: {}'.format(
            args.network_name, 
            ','.join(args.IPs))
    iplist.fromstr(targets)
    if args.output is not sys.stdout:
        args.output = open(args.output, 'w')

    do_scan = bool(args.no_scan) is None
    '''
    if args.no_scan is not None:
        iplist.fromnmapxml(args.no_scan)
        do_scan = False
    '''

    run(do_scan,
        args.discard_log, 
        args.output)
    # clean up
    if path.exists(hostspath):
        os.remove(hostspath)

