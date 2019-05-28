#!/usr/bin/python
"""
Server to serve nmap scans and other l2vis processing
This code is meant to be bilingual, since l2vis is Python3, but having
Python2 compatability is easier for systems with a python2 default.

Request JSON schema
{
	scan: {...},
	secret: '',
}
Response JSON schema
{
	result: '', //xml result file in string
	error: 0,
	error_desc: '',
}
"""

import sys
python2 = sys.version_info[0] == 2
python3 = sys.version_info[0] == 3
if not python2 and not python3:
	raise Exception('Unknown Python version')

if python2: import SocketServer as socketserverimport
elif python3: import socketserver 
ForkingTCPServer = socketserver.ForkingTCPServer
StreamRequestHandler = socketserver.StreamRequestHandler

import os
import subprocess as subproc
import re  # no pyparsing
import json
from tempfile import mkstemp
import logging

from __future__ import print_function

logformat = '%(asctime)-15s %(clientaddr)s %(user)-8s %(message)s'
logging.basicConfig(format=logformat)
logger = logging.getLogger('tcpserver')

ip = re.compile(r'')
iprange = re.compile(r'')
line = None
def validsyntax(input):
	"""validate the syntax of a request"""
	# TODO: implement
	return True

def validsecret():
	"""validate a request by its secret"""
	# TODO: implement
	return True

class L2VisNMAPHandler(StreamRequesthandler):
	"""Handle requests for network scans"""
	def __init__(self):
		self.error = 0
		self.error_desc = ''
		self.result = ''
	def handle(self):
		"""handle requests"""
		rawdata = self.rfile.read()
		data = json.loads(rawdata)
		scan = data['scan']
		secret = data['secret']
		if not validsecret(secret):
			self.secreterr()
		elif not validsyntax(scan):
			self.syntaxerr()
		else:
			try:
				hostpath, _ = mkstemp()
				outpath, _ = mkstemp()
				scan = ['/usr/bin/nmap', '--privileged', '-sn', '-Pn', '-T5', 
					'--traceroute', '-oX', outpath, '-iL', hostpath]
				subproc.check_output(scan)
				self.wfile.write(scanout)
				os.remove(hostpath)
				os.remove(outpath)
			except Exception as e:
				print(e)
				raise e
			logger.info('successful request')
	def syntaxerr(self):
		info = {'clientaddr': ''}
		logger.warning('Syntax Error', '', extra=info)			
	def secreterr(self):
		info = {'clientaddr': ''}
		logger.warning('Secret Error', '', extra=info)			
	# NOTE: have an unauthorized client error?
	def finishhandle(self):
		response = {
			'result': self.result,
			'error': self.error,
			'error_desc': self.error_desc
			}
		responsejson = json.dumps(response)
		self.wfile.write(responsejson)

allowedclients = 'REDACTED', 'REDACTED'

class L2VisNMAPServer(ForkingTCPserver):
	def __init__(self, addr):
		ForkingTCPServer.__init__(self, addr, L2VisNMAPHandler)
	def verify_request(request, client_address):
		result = False
		if client_address[0] in allowedclients:
			result = True
		return result
		
if __name__ == '__main__':
	HOST, PORT = 'localhost', 8991  # sys.hostname or something?
	server = L2VisNMAPHandler((HOST, PORT))
	server.serve_forever()

