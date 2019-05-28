
from netaddr import IPSet, IPNetwork
from trace import IPFile
import json

IPSet.__invert__ = lambda s : IPSet(IPNetwork('0.0.0.0/0')) - s

i = IPFile()
i.fromfile('private/REDACTED.ips')

t = json(open('REDACTED', 'r').read())

t['exclude'].clear()
t['exclude'].append('192.168.1.0/24')


compl = IPSet(IPNetwork('0.0.0.0/0'))
for ip in i:
    compl = compl & ~IPSet(IPNetwork(ip))

compl.compact()

t['exclude'].extend( (str(i) for i in compl.iter_cidrs()) )

with open('REDACTED2', 'w') as f:
    f.write(json.dumps(t))

# compl should be the complement of all the ips now
