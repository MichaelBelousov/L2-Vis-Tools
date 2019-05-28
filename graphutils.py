#!/usr/bin/python3
"""
A bunch of miscellanious utility functions and classes.
Some stuff from varying scripts will be moved here.

TODO:
    - complete block_pos
    - replace vec with some PyPI module, one's got to exist
        - otherwise, make val a function val(), and do not store x and y as a tuple
            it will add bugs for sure.
    ? move svg_from_nxgraph() to visio.py
    ? have some function specific imports?
    - rename this to like l2visutils
"""

import networkx as nx 
# import pydot
import os
from datetime import datetime as dt
import math
from pprint import pprint
from oset import oset
import svgwrite
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, ElementTree
# from hosttype import iconspathroot

# TODO: replace with an external library
class Vec:
    """
    A simple geometric 2D geometric vector object,
    should be replaced with an external library
    """
    def __init__(self, x=0, y=0):
        self.val = (x,y)
    def __str__(self):
        return str(self.val)
    def __repr__(self):
        return str(self)
    def __getitem__(self, key):
        if key in (0, 'x'):
            return self.val[0]
        elif key in (1, 'y'):
            return self.val[1]
        else:
            raise KeyError("A Vec element access is either 0,1,'x', or 'y'.")
    def __add__(self, other):
        assert type(other) == Vec, 'vectors can only be added to vectors'
        x = self[0]+other[0]
        y = self[1]+other[1]
        return Vec(x,y)
    def __mul__(self, other):
        # TODO: raise error instead of assert?
        # TODO: no cross product support error message?
        x = self[0]*other[0]
        y = self[1]*other[1]
        return Vec(x,y)
    def __sub__(self, other):
        return self + other.scale(-1)
    def scale(self, fact, yfact=None):
        if yfact is None:
            yfact = fact
        return Vec(self[0]*fact, self[1]*yfact)
    def __iter__(self):
        return iter(self.val)

def transformspace(pos, scale=(1,1), offset=(0.5,0.5)):
    """mutates a given pos dictionary by transforming the space to a rectangle
    defined by an offset (center) and a scale of the rectangle from the offset"""
    if not isinstance(scale, Vec):
        scale = Vec(*scale)
    if not isinstance(offset, Vec):
        offset = Vec(*offset)
    getx = lambda t: t[0]
    gety = lambda t: t[1]
    xmin = min(map(getx, pos.values()))
    xmax = max(map(getx, pos.values()))
    ymin = min(map(gety, pos.values()))
    ymax = max(map(gety, pos.values()))
    xrang = xmax-xmin
    yrang = ymax-ymin
    xmid = (xmax+xmin)/2
    ymid = (ymax+ymin)/2
    center = Vec(xmid, ymid)
    def t(k):
        p = Vec(*pos[k])
        p = p - center
        xscale = scale['x']
        yscale = scale['y']
        # TODO: evaluate if this is the right thing to do on a range of 0
        xfac = xscale/xrang if xrang != 0 else 1
        yfac = yscale/yrang if yrang != 0 else 1
        p = p.scale(xfac, yfac)
        p += offset
        pos[k] = p.val
    for k in pos:
        t(k)

class block_pos(dict):
    """
    a position mapping of nodes from G 
    using a layered block layout, to enforce
    padding for rooted network layout diagrams
    """
    def __init__(self, G, root):
        self._G = G
        tovisit = set(G.nodes())
        tovisit.remove(root)
        # table = UnboundedTable()
        width = 1
        table = [[root]]
        while tovisit:
            # get last row
            last = table[-1]
            # oset for unique and ordered hosts
            # nbrs = oset()
            nbrs = []
            # get all non-visited neighbors
            for n in last:
                nbrs += filter(lambda n: n in tovisit,
                        nx.neighbors(G,n))
            nbrs = oset(nbrs)
            tovisit -= nbrs
            # if there are no more nbrs, we're done
            if not nbrs:
                break

            # increase table size
            width = max(len(nbrs), width)
            itms = [i for i,itm in enumerate(last) if i is not None]
            # TODO: more pythonic rolling average
            # rolling avg(A, n) = A*n + t / n + 1
            # avg = sum((i for i,itm in enumerate(last) 
                # if i is not None))
            avg = sum(itms)//len(itms)

            # simulate unbounded table
            # there's likely a more pythonic way of doing this
            # expand previous rows
            for i, row in enumerate(table):
                if len(row) < width:
                    diff = width - len(row)
                    table[i] = ([None]*(diff//2)
                            + row
                            + [None]*(diff-diff//2)
                        )
            table.append([None]*width)
            table
            newrow = table[-1]
            # add them to the table near their parents
            for offset, nbr in enumerate(nbrs):
                newrow[offset-avg//2] = nbr

        # iter over table rotating (inverting
        for i, row in enumerate(table):
            for j, itm in enumerate(row):
                if itm is not None:
                    self[itm] = (j, i)

    def edge_pos(self):
        """
        return a map of edges (vertex pairs)
        to corresponding edge label positions
        """
        raise NotImplementedError()
        return {e:(0,0) for e in self._G.edges()}

    '''
    # creating svg canvas for this layout
    xmax = max((x[0] for x in pos.values()))
    xmin = min((x[0] for x in pos.values()))
    ymax = max((x[1] for x in pos.values()))
    ymin = min((x[1] for x in pos.values()))
    xrng = xmax - xmin
    yrng = ymax - ymin
    canvas = Vec(xrng*150, yrng*200)
    '''


class hierarchy_pos(dict):
    """
    a position mapping of nodes from G this class
    attempts to use a layering system to generate
    a readable network layout
    """
    def __init__(self, G, root):
        self[root] = (0.5, 1)
        tovisit = set(G.nodes())
        layers = [[root]]
        mid = self[root][0]
        while tovisit:
            top = layers[-1]
            # assemble next layer from top neighbors
            # this also sorts neighbors by connections to the top layer
            nbrs = []
            for n in top:
                nbrs += (i for i in nx.neighbors(G,n) if i in tovisit)
            # remove duplicates
            nbrs = oset(nbrs)
            # if we're out of neighbors, we're done
            if not nbrs:
                break
            # y distance is based on the layer sizes, and uses a logistic function
            ydist = -1.5/(1+math.exp(-4.5*abs(len(top)-len(nbrs))-1))
            xsize = 0
            xinc = 0
            if len(nbrs) > 1:
                xsize = 2*len(nbrs)
                xinc = xsize/(len(nbrs)-1)
            # placement:
            xcur = mid - xsize/2
            # get last y line from first element of top layer
            y = self[top[0]][1] - ydist
            newlayer = []
            for i, n in enumerate(nbrs):
                # alternating bumping to prevent horizontal collision
                if i%2==0:
                    y += 0.1*ydist
                else:
                    y -= 0.1*ydist
                tovisit.remove(n)
                newlayer.append(n)
                self[n] = (xcur, y)
                xcur += xinc
            layers.append(newlayer)
        transformspace(self)

def dot_from_nxgraph(G, pos, icons, types, labels, output, title='Title', meta={}):
    dot = nx.nx_pydot.to_pydot(G)
    dot.write(output, prog='fdp', format='svg')

# TODO: add custom exception type for some graphing issues?
# TODO: remove or refactor as necessary
def svg_from_nxgraph(G, pos, icons, types, labels, output, title='Title', meta={}):
    """
    Writes a networkx.Graph() object representing L2 topology 
    to an svg file. 
    pos: is a dictionary mapping nodes to positions
    icons: is a dictionary mapping nodes to svg icon file paths
    labels: is a dictionary mapping nodes to a string label
    output: is the path of an output file to write to
    title: is the title to be used in the graphic
    """
    # helper funcs
    # TODO: move to svgwriteplus
    def avgtxtsize(s):
        # XXX: completely relative to the font, 
        # this should be implemented else how
        return 6*len(s)
    def to_un(n, unit): 
        assert isinstance(unit,str)
        return str(n)+unit
    def from_un(n, unit):
        assert isinstance(unit,str)
        return float(n[:-len(unit)])
    to_cm = lambda n : to_un(n, 'cm')
    from_cm = lambda n : from_un(n, 'cm')
    to_px = lambda n : to_un(n, 'px')
    from_px = lambda n : from_un(n, 'px')
    to_percent = lambda n : to_un(100*n, '%')
    from_percent = lambda n : float(from_un(n, '%'))*0.01

    canvas = Vec(max(42*float(len(G))**1.05, 
                    700),
                max(28*len(G), 
                    100))

    svg = svgwrite.Drawing(size=(to_px(canvas['x']),
                            to_px(canvas['y'])),
                            debug=True)

    # add white background
    svg.add(svg.rect(size=('100%', '100%'),fill='white'))
    # amount of canvas padding for nodes
    pad = 0.25
    # invert and scale pos for SVG space
    pos = pos.copy()
    transformspace(pos,
        scale=(canvas['x']-pad*canvas['x'],
                canvas['y']-pad*canvas['y']),
        offset=(0.5*canvas['x'],
                0.5*canvas['y']))
    # NOTE move?
    for p in pos:
        pos[p] = (to_px(pos[p][0]), to_px(pos[p][1]))

    titleelem = svg.add(svg.text(title, 
                            insert=(to_px(canvas['x']*0.5 - 3*len(title)),
                                    to_px(canvas['y']*0.05)), 
                            fill='black'))
    # draw edges between/under nodes
    gedges = svg.add(svg.g(id='edges', stroke='black'))
    for edge in G.edges():
        p1 = (pos[edge[0]][0], pos[edge[0]][1])  
        p2 = (pos[edge[1]][0], pos[edge[1]][1])  
        gedges.add(svg.line(start=p1, end=p2))

    # draw nodes text, add metadata for node placement
    gnodes = svg.add(svg.g(id='nodes', style="""
    font-size:10;
    font-family:"Lucida Console", Monaco, monospace;
    stroke:black;
    stroke-width:0.6;
    fill:black
    """))

    # TODO: add config for all icons paths
    icondefs = {} 
    iconspathroot = 'icons/'  # XXX
    # add definitions for all icon types
    for icon in set(icons.values()):
        iconelem = svg.svg(id=icon, insert=(0,0))
        iconelem.set_desc(desc=icon)
        icondefs[icon] = iconelem
        svg.defs.add(iconelem)

    # icon sizes
    # XXX this is not a parameter, it's a constant based on the currently used pack
    iconsize = Vec(128,128)

    ###############################################################
    ###############################################################
    # FIXME:
    # somewhere, there are being added two copies of each node/text 
    # block. It isn't practically terrible, but it's stupid, find
    # it and remove it
    ###############################################################
    ###############################################################

    # add uses
    for node in pos:
        # XXX replace this default with the config
        thisnode = gnodes.add(svg.g())
        offset=40
        for ln in labels[node].split('\n'):
            if not ln: continue
            nodetxt = svg.text(ln, insert=pos[node])
            nodetxt.translate(-0.5*avgtxtsize(ln), offset)
            offset += 10
            thisnode.add(nodetxt)
        icon = icons.get(node, os.path.join(iconspathroot, 'osa_hub.svg'))  # XXX Too strong?
        iconelem = icondefs[icon]
        xy = pos[node]
        xy = (from_px(i) for i in xy)
        xy = tuple( (to_px(i) for i in (Vec(*xy)-(iconsize).scale(0.5))) )
        use = svg.use(iconelem, insert=xy)
        thisnode.add(use)
        gnodes.add(thisnode)

    # metadata
    for m in meta:
        val = meta[m]
        melem = Element(m)
        melem.text = val
        svg.set_metadata(melem)
    svg.set_desc(title, desc='A graph of an IP network made with the L2VisTools')

    # function for replacing dummy defs with actual icon svg
    def insert_icons(xmltree):
        defs = xmltree.find('defs')
        for d in defs:
            iconpath = d.attrib['id']
            iconelem = ET.fromstring(open(iconpath).read())
            # TODO: move viewbox to original use tag, and fix iconscale max!
            iconscale = 1/2  # icon scale  XXX does not work for values greater than 1!
            viewbounds = iconsize.scale(1/iconscale)
            viewbox = viewbounds.scale(-1/4).val + viewbounds.val  # tuple cat
            viewbox = ' '.join( (str(x) for x in viewbox) )
            iconelem.attrib['viewBox'] = viewbox
            d.append(iconelem)
    xml = svg.get_xml()
    insert_icons(xml)
    xml = ET.ElementTree(xml)
    xml.write(output)

