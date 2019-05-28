#!/usr/bin/python3
"""
This script takes existing data from trace.py, and generates spreadsheet
or spread-sheet importable/compatible data.
Currently it generates a spread-sheet compatible xml file:
tracetable.xml

TODO
    - make more generic for additional host data
    ? design an xlst filter for direct excel and other office suite import
        - this might be overkill, currently already using csv which
        - can probably be supported by special excel import
        - use .csv instead?
"""

from os import path
import sys
import trace
from xmltodict import parse as xmlparse, unparse as xmldump
import csv

tracepath = trace.resultpath
"""reference to path of the result of trace.py, from the module itself"""

# NOTE: not currently used
scanpath = trace.nmapxmlpath
"""path to nmap log generated during trace.py"""

tablepath = path.join(trace.root_dir, 'trace_table.xml')
"""NO LONGER IN USE: path of the resulting table xml file"""

tablecsv = path.join(trace.root_dir, 'trace_table.csv')
"""path of the resulting table csv file"""


def run(xml=None, output=tablecsv):
    """constructs a semi-colon delimited csv file from trace data"""
    if xml is None:
        xml = open(tracepath, 'rb').read()
    x = xmlparse(xml, force_list=trace.xmlforced)
    if isinstance(output, str):
        output = open(output, 'w')
    # use to separate network categories/add headings
    csvfile = csv.writer(output, lineterminator='\n')
    for network in x['networks']['network']:
        csvfile.writerow((network['networkname'],))
        csvfile.writerow(('hostname', 'address', 
                'type', 'trace'))
        if network['hosts'] is None:
            continue
        for host in network['hosts']['host']:
            csvfile.writerow((host['hostname'], host['address'],))
            csvfile.writerow(
                    (None, 
                    None, 
                    None, 
                    'index', 
                    'hostname', 
                    'address'))
            if host['trace'] is None:
                continue
            for hop in host['trace']['hop']:
                csvfile.writerow(
                        (None, 
                        None, 
                        None, 
                        hop['index'], 
                        hop['hostname'], 
                        hop['address']))
                # typedct.get(host['address'])) # host['traceblob'])
    output.close()
    # TODO: fetch data from more sources for the spreadsheets
    # TODO: integrate these two steps


if __name__ == '__main__':
    # if not path.exists(tracepath):
        # trace.run(do_scan=True, keep_logs=True)
    run(xml=sys.stdin.read(), output=sys.stdout)
