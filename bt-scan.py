# file: inquiry.py
# auth: Albert Huang <albert@csail.mit.edu>
# desc: performs a simple device inquiry followed by a remote name request of
#       each discovered device
# $Id: inquiry.py 401 2006-05-05 19:07:48Z albert $
#

import bluetooth
import time


def output(msg): 
    with open('scan.txt', 'a+') as f:
        print(msg, file=f)
        print(msg)


output("performing inquiry...")

while True:
    nearby_devices = bluetooth.discover_devices(
        duration=8, lookup_names=True, flush_cache=True, lookup_class=False)

    output("found %d device(s)" % len(nearby_devices))

    for addr, name in nearby_devices:
        try:
            output("  %s - %s" % (addr, name))
        except UnicodeEncodeError:
            output("  %s - %s" % (addr, name.encode('utf-8', 'replace')))

    time.sleep(30)