#!/usr/bin/python3

r"""
A script that runs the trace.py script
invokes the visio.py script to generate visualization SVGs and a cumulative PDF of the data.
Some other optional scripts are invoked to provide additional data for visio.py

OPTIONS
    -n/--no-scan:   don't perform the trace step, graph from existing data. This is nearly
                    equivalent to running trace.py with the same arguments, and then visio.py

    -k/--keep-scan-logs
                    don't delete the nmap scan xml logs used to generate the final product


TODO
    - finish proper implementation of command line execution options, e.g. don't rerun trace
    - choose then standardize use of trace vs. scan for the data aggregation step
    - add email-on-finish option to run.py

AUTHOR
    Michael Belousov
"""

import argparse
import trace, visio, hosttypes, sheet

def run(target, 
        do_scan=True, 
        keep_logs=False,
        email=False):
    trace.run(do_scan, keep_logs)
    hosttypes.run()
    sheet.run()
    visio.run()  # should return a file path to the produced svg?
    # get result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='A script that traces and graphs L2 data, see docstrings')
    parser.add_argument('-n', '--no-scan',
                        help='do not perform a new nmap scan',
                        action='store_true')
    parser.add_argument('-d', '--discard-log',
                        help="don't keep nmap's scan logs after tracing",
                        action='store_true')
    args = p.parse_args()
    do_scan = not args.no_scan
    keep_logs = not args.discard_log
    run(do_scan, keep_logs)
