"""
The .graph file format is a very simple, easy-to-write language 
for describing simple, text-labeled graphs, it just makes it easier
to hand copy graphs if necessary. These utilities convert
it to more standard formats like JSON or XML.

The graph file format is as follows:

# Comments

(Tree) 
# all following nodes belong to the above titled tree/graph
# the first following node is assumed to be the "root"

Node: neighbor1 [, neighbor2 ...] : key=value, key=value
# a node declaration is a name, with a list of neighboring nodes 
(or trees) after, and then an attributes mapping

# leaves can be excluded from the listing

"""

# TODO: redo the simple parsing with pyparsing

import json
from xmltodict import unparse as xmldump
from collections import OrderedDict as odict

def graphfile_to_JSON(f):
    """take a .graph file and output a JSON string"""
    content = open(f).read()
    raise NotImplementedError()

def graphfile_to_XML(f):
    """take a .graph file and output an XML string"""
    content = open(f)
    trees = []
    class NoTreeOdict(odict):  # OrderedDict that denies trees as leaf names
        def __setitem__(self,k,v):
            if k not in trees:
                return odict.__setitem__(self,k,v)
    done = NoTreeOdict()
    graphs = odict()
    graphs['graph'] = []
    root = odict(graphs=graphs)
    currgraph = None
    with open(f) as file:
        # TODO: add line counter for syntax error
        lines = file.readlines()
        # get trees here in first sweep
        for l in lines:
            l = l.strip()  # strip indentation
            l,_,_ = l.partition('#')  # strip comments
            if not l:
                pass
            elif l.startswith('('):  # line is a tree declaration
                # add stray leaves
                if currgraph is not None:
                    filt = filter(lambda t: not done[t], done)
                    for d in filt:
                        thisnode = odict()
                        thisnode['name'] = d
                        currgraph['nodes']['node'].append(thisnode)
                    done.clear()
                # start new currgraph
                currgraph = odict()
                title = l[1:-1]  # XXX: this is why pyparsing is needed
                graphs['graph'].append(currgraph)
                currgraph['title'] = title
                currgraph['nodes'] = odict()
                currgraph['nodes']['node'] = []
                trees.append(title)
                # everytime we find a new tree, prune spare nodes from previous trees
                for g in root['graphs']['graph']:  # XXX: this could take some time for large files
                    for n in g['nodes']['node']:
                        if n['name'] in trees:
                            del n
            elif ':' in l:  # line is a node declaration
                if currgraph is None:
                    raise SyntaxError('You have a node declaration before a title')
                label, _, nbrs = l.partition(':')
                nbrs = nbrs.split(',')
                nbrs = [n.strip() for n in nbrs]
                done.update({n:False for n in nbrs if n not in done})
                thisnode = odict()
                currgraph['nodes']['node'].append(thisnode)
                thisnode['name'] = label
                nbrslist = []
                thisnode['neighbors'] = odict()
                thisnode['neighbors']['neighbor'] = nbrslist
                for n in nbrs:
                    nbrslist.append(n)
                done[label] = True
            else:
                raise SyntaxError('Unknown expression during parsing')
    return xmldump(root, pretty=True)


if __name__ == '__main__':
    x = graphfile_to_XML('REDACTEDNetwork.graph')
    with open('REDACTEDNetwork.xml','w') as f:
        f.write(x)


