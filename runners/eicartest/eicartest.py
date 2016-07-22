import sys
import json
import requests
import tempfile
from scapy.all import *
from scapy.error import Scapy_Exception

if len(sys.argv) != 2:
    print >>sys.stderr, "Usage: {} <url>".format(sys.argv[0])
    sys.exit(1)

try:
    r = requests.get(sys.argv[1])
    if r.status_code >= 400:
        print json.dumps({"error": "File not found", "found": 0})
        sys.exit(2)
    with tempfile.NamedTemporaryFile() as temp:
        temp.write(r.content)
        temp.flush()
        packets = rdpcap(temp.name)
except requests.exceptions.RequestException as e:
    print json.dumps({"error": "Requests error", "found": 0})
    sys.exit(3)
except Scapy_Exception:
    print json.dumps({"error": "Scapy error", "found": 0})
    sys.exit(4)

EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

out = list()
for packet in packets:
    if EICAR in str(packet):
        out.append(json.dumps({"found": 1, 
                               "data": repr(packet.lastlayer().load)}))

if not out:
    out.append({"found": 0})

print json.dumps(out)
