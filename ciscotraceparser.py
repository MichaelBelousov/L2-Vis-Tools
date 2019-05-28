#! /usr/bin/env python3

"""
Utilities, including a Pyparsing-implemented grammar,
for parsing cisco router traceroutes (trace mac) into
XML for the visio script.

TODO:
    - present interface either as module, or cli
    - use argparse

CLI USAGE:
    
    ./ciscotraceparser < cmd_out.txt > out.xml

PYTHON USAGE:
    >>> outxml = traces_to_visoxml(trace_str, title='Title')
    
"""

__author__ = 'Michael Belousov'

############ trace mac grammar ##################

# TODO: enumerate the many used pyparsing elements
#
from pyparsing import *  
from functools import reduce
from operator import add
from xmltodict import unparse as xmldump
from collections import OrderedDict as odict
from netaddr import IPAddress

# set pyparsing base class to suppress string literals
# by default, e.g. '(' + Word(nums) + ')' will yield
# only the number
# ParserElement.inlineLiteralsUsing(Suppress)

def perLine(elem):
    """
    convenience function equivalent to OneOrMore(Group(...))
    """
    return OneOrMore(Group(elem))

def seq(*args):
    """
    vararg sum, to prevent ugly "A+B+C+..",
    this is a style choice
    """
    return reduce(add, args)
    # TODO: use sum instead of reduce, 
    # return sum(args, Empty())

# TODO: remove (this isn't used)
def CombineSpaced(*args):
    """
    Combine but allow spacing, so you still get one parsed
    token
    """
    def intersperse(itr, delim):
        it = iter(itr)
        yield next(it)
        for x in it:
            yield delim
            yield x
    print(intersperse(args, Optional(White())))
    return Combine(*intersperse(args, Optional(White()))) 

# suppressed chars:
LPAR, RPAR, LBRACK, RBRACK, PERIOD, COMMA = (
        map(Suppress, r"""()[].,""")
    )
BSLASH, FSLASH, HASH, DASH, DQUOTES, SQUOTE, QUESMARK  = (
        map(Suppress, r"""\/#-"'?""")
    )

# I prefix patterns by 'p_', as a personal convention,
# to differentiate them from parsed data

# shorthand for literal
L = lambda t: Literal(t)

# url
# FIXME: use official regex definitions of URI grammar
p_url = seq(
        Word(alphas)                        ('protocol'),
        Suppress('://'),
        Word(alphanums+'._-')               ('domain'),
        Optional(
            Word(alphanums+'._-/')          ('resource')
            + Optional(
                QUESMARK
                + Word(printables)          ('url_params')
                ))
    )

# TODO: parse IPs to IPAddr objects from netaddr module

class hexint(int):
    """A hexidecimal represented integer"""
    def __str__(self):
        return hex(self)
    def __repr__(self):
        return str(self)

def makestrcmper_class(cls):
    """A wrapper around types that makes string 
    representation comparisons equivalent to regular 
    comparisons"""
    class StrCmper(cls):
        def __eq__(self, other):
            if isinstance(other, str):
                return str(self) == other
            else:
                return super().__eq__(other)
    StrCmper.__name__ = f'StrCmper({cls.__name__})'
    StrCmper.__doc__ = makestrcmper_class.__doc__
    return StrCmper

def makestrcmper(cls, *args, **kwargs):
    strcmpercls = makestrcmper_class(cls)
    return strcmpercls(*args, **kwargs)

p_number = Word(nums)
p_number.setParseAction(lambda s,l,t: int(t[0]))

# hex
p_hex = Word(nums+'abcdefABCDEF')
# p_hex.setParseAction(lambda s,l,t:hex_int(t[0]))
p_hexliteral = Combine('0x'+p_hex)
# hostname, might require more characters
p_hostname = Word(alphanums+'_-.')                          ('hostname')
# mac address
p_mac = delimitedList(p_hex, '.', combine=True)             ('mac')
# ip address
p_ip = delimitedList(Word(nums), '.', combine=True)         ('ip')

# NOTE: this is how it will be done in the future
# p_ip.setParseAction(lambda s,l,t: makestrcmper(IPAddress, t[0]))

# the ways vlans are identified in output
p_vlan = (L('Vl') ^ L('Vlan')) + Word(nums)                 ('vlan_id')

# FIXME: I need to learn the vocabulary here
# VSS Ports:
# Unit/Blade/Port
p_interface = seq(
        (
            L('GigabitEthernet')
            ^ L('Gi')
            ^ L('Fa')
        )                                   ('type'),
        Word(nums)                          ('unit'),
        FSLASH,
        Word(nums)                          ('blade'),
        Optional(
            FSLASH
            + Word(nums)                    ('port')
            )
    )

# TODO: add type parse action

p_interfacedesc = seq(
        'interface',
        Word(alphanums+'.-_/')              ('interface_name'),
        'description',
        OneOrMore(Word(printables))         ('desc'),
            FollowedBy(lineEnd),
        'encapsulation',
        'ip vrf forwarding',
        'ip address',
        'ip helper-address'
        # ...
    )

p_interfaceabbrev = p_interface

# FIXME: ports/interfaces
p_Po = Combine(
        Literal('Po') 
        + Word(nums)        ('po_id')
        )

# FIXME: need to know this vocab
p_port = p_vlan | p_interfaceabbrev | p_Po

# to the uninitiated, 
# ParserElement.__call__ = ParserElement.setResultsName
# a hop in the trace route
p_hop = seq(
        Word(nums)          ('index'),
        p_hostname          ('host'),
        '(',
        p_ip,
        ')',     
        ':',
        p_port              ('inbridge'),
        '=>',
        p_port              ('outbridge')
    )


p_prompt = seq(
        p_hostname              ('host'),
        HASH
)

######################################################

p_tracemac_prompt = seq(
        p_prompt,
        Literal('trace mac')        ('cmd'),
        p_mac                       ('src_mac'),
        p_mac                       ('dest_mac'),
        'vlan',
        Word(nums)                  ('vlan'),
        )

# actual full trace mac command grammar from previous stuff
p_tracemac_success = seq(
        p_tracemac_prompt,

        Optional(
            Group(
                seq(
                    'Source',
                    p_mac,
                    'found on',
                    p_hostname)))   ('src_found'),

        OneOrMore(Group(p_hop))     ('hops'),

        Optional(
            Group(
                seq(
                    'Destination',
                    p_mac,
                    'found on',
                    p_hostname)))   ('dest_found'),

        Suppress('Layer 2 trace completed')
    )

# destination not found error
p_tracemac_err = seq(

        p_tracemac_prompt,
        
        # TODO: add error checking to success obj
        'Error: ' ,
        restOfLine                  ('err'),

        # separated in case there is no space between Layer and 2
        Optional(
            Suppress(
                Literal('Layer')
                + Literal('2')
                + Literal('trace aborted.')
                )
            )
    )

p_tracemac_err_src= seq(
        p_prompt,
        Literal('trace mac')        ('cmd'),
        p_mac                       ('src_mac'),
        p_mac                       ('dest_mac'),
        'vlan',
        Word(nums)                  ('vlan'),
        
        Literal(
            'Source and Destination on same port and no nbr!')
                                    
                                    ('err')
        )

p_tracemac = ( 
        p_tracemac_success 
        ^ p_tracemac_err 
        ^ p_tracemac_err_src
    )

# multiple traces across a file on separate lines
p_tracemacs = OneOrMore(Group(p_tracemac))

############ end trace mac grammar ##################

############ span grammar ##################

p_spansect = seq(
        Word(alphas)                            ('name'),
        'ID',
        'Priority',
        Word(nums)                              ('priority'),
        'Address',
        p_mac,
        Optional(
            'This bridge is the root')          ('root'),
        'Hello Time',
        Word(nums)                              ('hello_time'),
        Word(alphas)                            ('hello_time_units'),
        'Max Age',
        Word(nums)                              ('max_age'),
        Word(alphas)                            ('max_age_units'),
        'Forward Delay',
        Word(nums)                              ('forw_delay'),
        Word(alphas)                            ('forw_delay_units'),
        Optional(
            'Aging Time'
            + Word(nums))                       ('aging_time'),
    )

p_spaninterf = seq(
        Combine('Po' + Word(nums))                          ('interface'),
        Literal('Desg')                                     ('role'),
        Literal('FWD')                                      ('sts'), 
        Word(nums)                                          ('cost'), 
        Combine(Word(nums) + PERIOD + Word(nums))           ('priority'), 
        Literal('P2p')                                      ('type')
    )

p_spancmd = seq(
        'VLAN' + Word(nums)                    ('vlan'),
        'Spanning tree enabled protocol' + Word(alphas) ('tree_protocol'),
        OneOrMore(Group(p_spansect)),
        'Interface', 'Role', 'Sts', 'Cost', 'Prio.Nbr', 'Type',
        OneOrMore(Group(Word('-'))),
        OneOrMore(Group(p_spaninterf))
    )

############ end span grammar ##################

############ show cdp neighbor grammar ##################

p_platform = 'cisco' + Word(alphanums+'_-./')                  ('platform')
p_capability = (
        Empty() 
        | 'Router'
        | 'Switch'
        | 'IGMP'
        | Word(alphas+'_-.')
    )
# TODO: fix other interface
p_real = Combine(Word(nums) + Optional('.' + Word(nums)))
p_time = (
        p_real                      ('value')
        + Word(alphas)              ('unit')
    )

p_iosversion = seq(
        'Cisco IOS Software',
        COMMA,
        Word(alphas)                ('class'),
        'Software',
        LPAR,
        Word(printables)            ('build'),
        RPAR,
        COMMA,
        'Version',

        p_real                      ('version'),
        LPAR,
        Word(nums)                  ('patch'), # FIXME: is this correct?
        RPAR,
        Word(alphas) + Word(nums)   ('extension'),  # FIXME: ditto
        COMMA,
        'RELEASE SOFTWARE',
        LPAR,
        Word(alphanums)             ('code'),
        RPAR
    )                               ('ios_version')

p_cdpneigh = seq(

        Suppress(Word('-')),  # pretty header

        'Device ID:', p_hostname                    ('device_id'),

        'Entry address(es):',
        OneOrMore(Group(
            'IP address:' + p_ip
            ))                                      ('ip_entries'),

        'Platform:', p_platform, COMMA,
        'Capabilities: ', OneOrMore(p_capability)   ('capabilities'),

        'Interface: ', p_interface, COMMA, 
        'Port ID (outgoing port):', p_interface,
        
        'Holdtime :', p_time                        ('hold_time'),

        'Version :', p_iosversion,

        'Technical Support:',   p_url               ('support_site'),

        'Copyright (c)', 
        Word(nums)                                  ('copyright_start'),
        DASH,
        Word(nums)                                  ('copyright_end'),
        'by Cisco Systems, Inc.',
        
        'Compiled',
        Combine(Word(alphas)
            + White()
            + Word(alphanums+'-_/.')
            + White()
            + Word(nums+':.'))                      ('compilation_date'),
        Word(alphanums+'_-.')                       ('compilation_team'),

        'advertisement version:',
        Word(nums)                                  ('ad_version'),
        
        'Protocol Hello:',
        'OUI=', p_hexliteral                        ('OUI'),
        COMMA,
        'Protocol ID=', p_hexliteral                ('protocol_id'),
        'payload len=', Word(nums)                  ('payload_len'),
        'value=', p_hex                             ('value'),

        'VTP Management Domain:', 
        SQUOTE, 
        p_hostname                                  ('mgmt_domain'), 
        SQUOTE,

        'Native VLAN:',
        Word(nums)                                  ('native_vlan'),

        'Duplex:',
        Word(alphas)                                ('duplex'),

        'Management address(es):',
        OneOrMore(Group(
        'IP address:' + p_ip
        ))                                          ('mgmt_ips')

    )

############ end cdp neighbors grammar ##################

############ show ip arp vrf grammar ##################

# p_proctocol = Literal('Internet') | Literal('...')
p_protocol = Word(alphas)
p_age = Word(nums) | '-'
# p_arptype = 'ARPA'...
p_arptype = Word(alphas)
p_arpinterface = p_vlan | Combine(
        'Port-channel' + Word(nums) + '.' + Word(nums)) 

p_entry = seq(
        p_protocol          ('protocol'),
        p_ip                ('ip'),
        p_age               ('age'),
        p_mac               ('mac'),
        p_arptype           ('type'),
        p_arpinterface      ('interface')
    )

p_showipcmd = seq(
        p_prompt,  # XXX: remove inclusion of prompts in grammar
        Literal('show ip arp vrf')      ('cmd'),
        p_hostname                      ('asset'),

        Empty(),  # Prevent string comp

        # output column headers
        'Protocol', 'Address', 'Age (min)', 
        'Hardware Addr', 'Type', 'Interface',

        OneOrMore(Group(p_entry))       ('entries'),
    )

############ end show ip arp vrf grammar ##################

################## snmp walk grammar ######################

p_oid = delimitedList(Word(nums), '.')
p_mib = Word(alphanums+'-_')
p_english_oid = delimitedList(Word(alphanums), '.')
p_oid_counter = 'Counter' + Word(nums)
p_oidtype = p_oid_counter  # | ...
p_oidval = Word(nums)
p_snmpver = (
        Combine(p_number, ('version')  
        + Optional('c'))
        )

p_snmpv2walkcmd = seq(
        p_prompt,
        Literal('snmpwalk')         ('cmd'),
        '-v', p_snmpver             ('snmp_version'),
        '-c', Word(alphanums)       ('community'),
        p_hostname                  ('target_host'),
        p_oid                       ('target_oid'),

        p_mib                       ('mib'),
        '::', 
        p_english_oid               ('oid'),
        '=',
        p_oidtype                   ('oid_type'),
        ':',
        p_oidval                    ('oid_value')
    )

################ end snmp walk grammar ####################


# TODO: use parseAction on p_prompt in command grammars to 
# embed arguments data

p_cmd = OneOrMore(
            # p_prompt +
            ( 
                p_showipcmd             ('show_ip')
                | p_tracemacs           ('traces')
                )
            )

#################### end grammars ########################

# TODO: if trace errors (parse fails), print input

def log_to_visioxml(traces, title=None):
    """convert cisco trace mac output to a 
    visio-structured XML doc"""

    # cisco router log excerpts on whatsup generally have the
    # procedural exhaustive equivalent structure to:
    # $ show ip && for mac in $(show ip); do trace mac "$mac"; done
    parsed = p_cmd.parseString(traces, parseAll=True)
    # need to check PEP8 for that one...

    if title is None:
        title = parsed['show_ip']['asset']

    # map macs to ips to prevent future linear searches
    mac_to_ip = {}
    for entry in parsed['show_ip']['entries']:
        if entry['mac'] in mac_to_ip:
            mac_to_ip[entry['mac']].append(entry['ip'])
        else:
            mac_to_ip[entry['mac']] = [entry['ip']]

    # construct XML (that's what all the
    # list and odict composition is)
    xml = odict()
    xml['networks'] = odict()
    xml['networks']['network'] = []
    thisnet = odict()
    xml['networks']['network'].append(thisnet)

    thisnet['networkname'] = f'{title}_{parsed["host"]}'
    thisnet['hosts'] = odict()
    thisnet['hosts']['host'] = []

    for trace in parsed['traces']:

        # disregard error traces
        if 'err' in trace:
            continue

        host = odict()
        thisnet['hosts']['host'].append(host)

        # set host data
        # if there are multiple addresses, use them as one name
        host['hostname'] = ','.join(mac_to_ip[trace['dest_mac']])
        host['address'] = ','.join(mac_to_ip[trace['dest_mac']])

        host['trace'] = odict()
        host['trace']['hop'] = []

        # go through hops
        for hop in trace['hops']:  # NOTE: used to skip hop 1
            host['trace']['hop'].append(
                    odict(
                        index=int(hop['index']), 
                        hostname=hop['host'], 
                        address=hop['ip']))

    return xmldump(xml, pretty=True)


if __name__ == '__main__':
    from sys import stdin
    print(log_to_visioxml(stdin.read()))


