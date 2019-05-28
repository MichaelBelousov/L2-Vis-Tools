"""
Server which takes requests for L2VisScans from authenticated
sources, runs them, and responds with the SVGs

TODO
    - connect L2Vis
    ? add support for returning the scan XML file?
"""

__author__ = 'Michael Belousov'

import socketserver
from socketserver import ForkingTCPServer, StreamRequestHandler
import logging
from configparser import ConfigParser
import re
import sys
import trace, visio

log = logging.getLogger(__name__)
"""Log for debugging and information purposes"""

CONF_FILE = ''

CONF_SECT = ''

HOSTNAME = 'localhost'
"""Server hostname configuration"""

PORT = 8313
"""Server port configuration"""

SECURITYAPPS_IP = ''
"""Security apps IP"""

secret = ''
"""Secret for secure access from trusted hosts"""

parser = SafeConfigParser()
parser.read(CONF_FILE)
secret = parser.get(CONF_SECT, 'secret')


p_ipv4 = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
p_iprange = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}-(?:\d{1,3}\.){3}\d{1,3}')
p_ipcidr = re.compile(r'(?:\d{1,3}\.){3}\d{1,3}')
def isvalidsyntax(line):
    try:
        line = str(line)
        # import code
        # code.interact(local=locals())
        ips = line
        label = 'misc'
        if ':' in line:
            label, _, ips = line.partition(':')
        label = label.strip()
        ips = ips.strip()
        ips.split(',')
        ips = (ip.strip() for ip in ips)
        # check that all ips match some (allowed) pattern
        result = all((i for i in ips 
                        if p_ipv4.match(i) 
                        or p_iprange.match(i) 
                        or p_ipcider.match(i)))
    except Exception as e:
        print('Exception: {}'.format(e))
        result = False
    return str(result)

class L2VisHandler(StreamRequestHandler):
    def handle(self):
        clientaddr = self.client_address[0]
        log.info('Request from {}'.format(clientaddr))
        for line in self.rfile:
            line = line.strip()
            valid = isvalidsyntax(line)
            self.wfile.write(bytes(valid, 
                encoding=sys.getdefaultencoding()))

class L2VisServer(ForkingTCPServer):
    def __init__(self, hostname, port):
        super().__init__((hostname, port), L2VisHandler)


if __name__ == '__main__':
    server = L2VisServer(HOSTNAME, PORT)
    server.serve_forever()
