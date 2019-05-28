#!/usr/bin/python3
'''
This script generates svgs and pdfs from the scan.xml file generated by scan_to_xml.py
all the formatting is done here.

TODO
    - test metadata in svgs
    - organize this properly
'''

from xmltodict import parse as xmlparse, unparse as xmldump
import networkx as nx
from os import path
import sys, os
from datetime import datetime as dt
from trace import xmlforced, root_dir
from hosttype import choose_icons_and_types
from graphutils import hierarchy_pos, svg_from_nxgraph
import subprocess as subproc
import argparse

# TODO: raise informative error exception on inkscape dependency
# from PyPDF2 import PdfFileMerger, PdfFileReader
# FIXME: not sure if this currently works, hasn't been used since many changes
def svgstopdf(svgs, metadata={}):
    """construct a single PDF from the multiple SVGs"""
    # process svg output, format, save as compiled pdf
    docname = "REDACTED-L2-Topology.pdf"
    merger = PdfFileMerger()
    for f in svgs:
        # generate pdf
        newf = '{}.pdf'.format(path.splitext(f)[0])
        try:
            p = subproc.call(['/usr/bin/inkscape', f, '--export-pdf', newf])
        except Exception as e:
            # TODO: no inkscape error
            sys.exit(1)
        p = PdfFileReader(open(newf, 'rb'))
        print('a pdf was generated')
        merger.append(p)
        os.remove(newf)
    d = {}
    d['Author'] = u'Michael Belousov'
    d['Subject'] = u'REDACTED network infrastructure'
    d['Keywords'] = u'REDACTED Network L2'
    d['CreationDate'] = str(dt(2017,9,27))
    d['ModDate'] = str(dt.today())
    merger.addMetadata(metadata)
    merger.write(docname)

def visfromtracexml(xmlfile, format='svg', outpath=os.curdir, metadata={}):
    """takes a file descriptor of an XML file generated by trace.py and
    graphs each network in it as an SVG"""
    xmldata = xmlparse(xmlfile, force_list=xmlforced)
    # generate graph data from trace.xml
    graph_dump = []
    for net in xmldata['networks']['network']:
        G = nx.Graph()
        labels = {}  # dict mapping nodes to labels
        # construct new graph
        # I opted to use continue's because the depth gets
        # unwieldy for proper if statements.
        if net['hosts'] is None: 
            continue
        for host in net['hosts']['host']:
            # construct the topology for the relevant hosts
            labels['PUBLIC'] = 'PUBLIC'  # root of all traces
            last = 'PUBLIC'
            if host['trace'] is None: 
                continue
            for hop in host['trace']['hop']:
                G.add_edge(last, hop['address'])
                labels[hop['address']] = f'{hop["hostname"]}'\
                                        '\n{hop["address"]}'
                last = hop['address']
            G.add_edge(last, host['address'])
            labels[host['address']] = f'{host["hostname"]}'\
                                     '\n{host["address"]}'
        graph_dump.append( (G, net['networkname'], labels) )
    # convert each to the appropriate format
    files= []
    for G, netname, labels in graph_dump:
        pos = {}
        # icons = {}
        icons, types = choose_icons_and_types(labels)
        pos = hierarchy_pos(G, 'PUBLIC')
        filename = path.join(outpath, f'{netname}.{format}')
        svg_from_nxgraph(G, 
                        pos, 
                        icons, 
                        types,
                        labels, 
                        filename,
                        f'{netname} Network',
                        metadata)
        files.append(filename)
        print(filename)
        # TODO: add exception handling for bad graphs
    print('finished successfully')
    return files

def run(inputxml, outpath, metadata={}):
    files = visfromtracexml(inputxml, 
            format='svg', 
            outpath=outpath, 
            metadata=metadata)
    return files
    # pdf = svgstopdf(svgs)

if __name__ == '__main__':
    # command line arg setup
    # TODO: validate input
    p = argparse.ArgumentParser(
        description='A script that traces L2 data, see docstrings')
    p.add_argument('-od', '--output-directory',
        help='directory to write output file(s)', default='./')
    p.add_argument('file', default=None, nargs='*',
        help='xml files (generated by trace.py) from which to generate graphs, ' 
        'stdin by default')
    # TODO: ensure this isn't somehow injectable when called
    p.add_argument('-m', '--metadata', default=None,
        help='metadata for generated SVG in form: key1=value1&key2=value2')
    args = p.parse_args()

    # structure metadata
    metadata = {}
    # TODO: change metadata argument format
    # currently done URL style, k1=v1&k2=v2&...
    # could be done in a more json/python style with k1:v1,k2:v2,...
    # better yet, allow for random named options as keys
    # with value arguments, e.g.:
    # ./visio.py -od outdir --author "Michael Belousov" \
    #       --company your_company-- target.xml
    # would yield a metadata dict as follows:
    # metadata = {
    #     'author': 'Michael Belousov',
    #     'company': 'your_company'
    # }
    if args.metadata is not None:
        for p in args.metadata.split('&'):
            k, _, v = p.partition('=')
            metadata[k] = v

    outdir = os.path.abspath(args.output_directory)

    # if no files, use stdin
    if not args.file:
        run(sys.stdin.read(), 
                outdir, 
                metadata)
    else:
        for f in args.file:
            run(open(f, 'rb').read(), 
                    outdir, 
                    metadata)
