#!/usr/bin/env python3

"""
Connect to a cisco router and generate xml for visio.py
by following mac traces to arp entries
"""

__author__ = 'Michael Belousov'

from getpass import getpass
from netmiko import ConnectHandler
from ciscotraceparser import log_to_visioxml
from ciscotraceparser import p_showipcmd
# from ciscotraceparser import ParseException
import argparse
import os, sys
import traceback
import visio
import sheet

debug = False
"""global storing whether the script is 
running in debug mode or not"""

maxtracetries = 2
"""maximum amount of retries for a failed
trace command"""

default_conn= {
        'device_type':      'cisco_ios',
        'port':             22,
        'default_enter':    '\r\n',
        'verbose':          False
        }
"""default cisco connection options for netmiko"""


def CiscoPromptConnectHandler(*args, **kwargs):
    """
    utility function to create an SSH connection
    with default options and prompts for empty
    manadated ones
    """
    connargs = default_conn.copy()
    connargs.update(kwargs)
    print(f'logging into {kwargs["ip"]}')
    if 'username' not in connargs:
        connargs['username'] = input('username: ')
    if 'password' not in connargs:
        connargs['password'] = getpass('password: ')
    try:
        result = ConnectHandler(*args, **connargs)
        result.ansi_escape_codes = True
        # set terminal length to 0 for scriptable output
        result.send_command('terminal length 0')
        return result
    except Exception as e:
        print('failed to connect with exception:')
        raise


# TODO: validate and replace if possible
def output_as_cmd(cmd, out):
    """rebuild the missing command prompt, and strip
    off the next one from a command's output"""
    lines = out.split('\n')
    # create last command prompt
    prompt = lines[-1]
    # remove next command prompt
    out = '\n'.join(lines[:-1])
    # compose
    return f'{prompt}{cmd}\n{out}\n'


def trace_arps(router, ssh, arps, outdir=os.curdir):
    """
    given an arp table, for a vrf, and an ssh connection, 
    cisco-tracemac all of the IPs, and save the network
    graph, log, and xml to outdir
    """
    log = arps
    # TODO: automagically rerun ssh flops here too?
    parsed = p_showipcmd.parseString(arps, 
            parseAll=True)
    vrf = parsed['asset']
    root = None
    try: 
        root, = (
            e for e in parsed.entries if 
            e.age == '-' and 
            # TODO: interface types in grammar
            e.interface.startswith('Port'))
    except Exception as e:
        print(f'could not detect {vrf} root')
        raise
    vlid = None
    try:
        vlid = [
            e.vlan_id for e in parsed.entries if
            'vlan_id' in e][0]
    except Exception as e:
        print(f'could not find vlan id for {vrf}')
        raise
            
    # iter over non-root entries and trace mac
    for entry in parsed.entries[1:]:
        src = root.mac  # aliased cuz line size
        dst = entry.mac
        cmd = f'trace mac {src} {dst} vlan {vlid}'
        out = ssh.send_command(cmd)
        log += output_as_cmd(cmd, out)

    # write command log
    prefix = f'{router}_{vrf}'
    ciscotracefile = f'{prefix}.ciscotrace'
    with open(os.path.join(outdir, ciscotracefile), 'w') as f:
        f.write(log)
    print(f'written to {ciscotracefile}')

    # write trace xml
    try:
        xml = log_to_visioxml(log)
    except Exception as e:
        # weird, right? well basically, if the function
        # failed, that probably just means a couple of 
        # lines were jumbled by netmiko. This recursion 
        # will automatically rerun it for you so you don't 
        # have to, isn't likely to fail twice, but there 
        # is some global retry cap to prevent anything silly
        global tries
        try:
            tries += 1
        except NameError:
            tries = 1
        if tries <= maxtracetries:
            print('retrying scan...')
            trace_arps(router, ssh, arps, outdir=os.curdir)
            tries = 0
            return
        else: 
            raise

    xmlfile = os.path.join(outdir, f'{prefix}.xml')
    with open(xmlfile, 'w') as f:
        f.write(xml)
    print(f'{vrf} written in xml')

    # write graph svg
    # TODO: better handling of this
    try:
        visio.run(xml, outdir, metadata={})
    except TypeError as e:
        xml = f"""\
                <networks>
                    <network>
                        <networkname>
                        {vrf}_{router}
                        </networkname>
                        <hosts>
                            <host>
                                <hostname>{root}</hostname>
                                <address>{root}</address>
                                <trace></trace>
                            </host>
                        </hosts>
                    </network>
                </networks>
                """
        visio.run(xml, outdir, metadata={})
        print(f'vrf data ungraphable, using base instead')
    print(f'{vrf} graphed')

    # write csv
    csvfile = os.path.join(outdir, f'{prefix}.csv')
    sheet.run(xml, csvfile)
    print(f'{vrf} tabled')


def scan(username, password, router, vrfs, outdir):
    """query the router for the cam tables of the 
    following vrfs, and return an XML string of
    the vrf's composition for visio graphing"""
    with CiscoPromptConnectHandler(
                username=username,
                password=password,
                ip=router,
                **default_conn) as ssh:
        print(f'Querying Router {router}...')
        for vrf in vrfs:
            log = ''
            print(f'Visualizing {vrf}...')
            # get arp cache for vrf
            cmd = f'show ip arp vrf {vrf}'
            out = ssh.send_command(cmd)
            log = output_as_cmd(cmd, out)
            try:
                log = trace_arps(router, ssh, log, outdir)
            except Exception as e:
                print(f'{vrf} scan failed')
                print(e)
                traceback.print_exc(file=sys.stdout)
            print(f'done visualizing {vrf}...')
            print()


if __name__ == '__main__':

    p = argparse.ArgumentParser(
            description='a utility for tracing active hosts in router vrfs')
    p.add_argument('-r', '--router', default='REDACTED',
            help='router to query')
    p.add_argument('VRFs', type=str, nargs='+',
            help='vrfs to scan')
    p.add_argument('-d', '--debug', action='store_true',
            help='activate debug mode for verbose errors')
    p.add_argument('-o', '--outdir', default=os.curdir,
            help='router to query')
    args = p.parse_args()

    username = input('Username: ')
    password = getpass('Password: ')
    debug = args.debug

    scan(username, password, args.router, args.VRFs, args.outdir)
