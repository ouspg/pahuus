#!/usr/bin/python

import sys
import json
import requests
import tempfile
from scapy.all import rdpcap
from scapy.error import Scapy_Exception

if len(sys.argv) != 2:
    print >>sys.stderr, "Usage: {} <url | pcap file>".format(sys.argv[0])
    sys.exit(1)

source = sys.argv[1]

try:
    if source.startswith('http://') or source.startswith('https://'):
        r = requests.get(source)
        if r.status_code >= 400:
            print json.dumps(
                {"meta":
                 {"error":
                  "File not retrieved (status code {})".format(r.status_code),
                  "found": 0}
                 })
            sys.exit(2)
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(r.content)
            temp.flush()
            packets = rdpcap(temp.name)
    else:
        packets = rdpcap(source)
except requests.exceptions.RequestException as e:
    print json.dumps({"meta": {"error": "Requests error", "found": 0}})
    sys.exit(3)
except (Scapy_Exception, NameError) as e:
    print json.dumps({"meta": {"error": "Scapy error %s" % e, "found": 0}})
    sys.exit(4)

EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='.decode('base64')

found = 0

meta = dict()
data = list()
for packet in packets:
    if EICAR in str(packet):
        found += 1
        data.append({"payload": repr(str(packet)), "time": packet.time})

meta["found"] = found

print json.dumps({'meta': meta, 'data': data})
