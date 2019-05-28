"""
This script uses basic pattern matching to guess the host types of a network.
The output usually needs to be human edited before used.
The visio.py script uses the data this generates to choose icons for its diagrams.

TODO
    - Pull this data/generate it from somewhere if possible
    - add override functionality during generation
    - use a config file to make a mapping of regex patterns to icons
"""

import re
from xmltodict import parse as xmlparse
from pprint import pprint
from os import path
# TODO: for collecting more data on hosts
from validators.ip_address import ipv4 as isipv4
from validators.domain import domain as isdomain
from trace import xmlforced, resultpath

# TODO: use a config for mapping types to icon paths,
# and have defaults
iconspathroot = 'icons/'
"""root of the icons path"""

# TODO: use actual node placement for detecting
# if something is a switch
# FIXME: validate naming scheme
vlan = re.compile(r'REDACTED')
vss = re.compile(r'REDACTED')
fw = re.compile(r'REDACTED')

def set_iconspath(path):
    """ set the path for icons, currently doesn't do 
    much since the names are hardcoded literals """
    iconspathroot = path

def choose_icons(labels):
    """ given a dicitionary of node names and ips,
    return a dictionary of nodes to node type strings"""
    icons = {}
    fromicons = lambda s: path.join(iconspathroot, s)
    for hostname, _ in labels.items():
        icon = ''
        if isdomain(hostname):
            if fw.findall(hostname):
                icon = fromicons('osa_firewall.svg')
            elif vlan.findall(hostname):
                icon = fromicons('osa_vpn.svg')
            # the icon just looks like a switch, will be changed
            elif vss.findall(hostname):
                icon = fromicons('osa_ics_plc.svg')
            else:
                icon = fromicons('osa_server.svg')
        elif isipv4(hostname):
            icon =  fromicons('osa_server.svg')
        else:
            icon = fromicons('osa_server.svg')
        icons[hostname] = icon
    icons['PUBLIC'] = fromicons('osa_cloud.svg')
    return icons


def choose_types(labels):
    """given a dicitionary of node names and ips,
    return a dictionary of nodes to node type strings"""
    types = {}
    for hostname, _ in labels.items():
        type_ = ''
        if isdomain(hostname):
            if fw.findall(hostname):
                type_ = 'firewall'
            elif vlan.findall(hostname):
                type_ = 'vlan'
            elif vss.findall(hostname):
                type_ = 'switch'
            else:
                type_ = 'misc'
        elif isipv4(hostname):
            type_ = 'misc'
        else:
            type_ = 'misc'
        types[hostname] = type_
    types['PUBLIC'] = 'not-a-host'
    return types


def choose_icons_and_types(labels):
    """
    returns icons and types for a node label set as a tuple
    literally: return choose_icons(labels, choose_types(labels)
    """
    return choose_icons(labels), choose_types(labels)
