#!/usr/bin/env python3

from __future__ import print_function
from scapy.all import *
from netaddr import *
# import netaddr

# Define IP range to ping
network = '192.168.1.0/24'

# make list of addresses out of network, set live host counter
addresses = IPNetwork(network)
liveCounter = 0

# Send ICMP ping request, wait for answer
for host in addresses:
    if (host == addresses.network or host == addresses.broadcast):
        # Skip network and broadcast addresses
        continue

    resp = sr1(IP(dst=str(host))/ICMP(),timeout=2,verbose=0)

    if resp is None:
        print(host, 'is down or not responding.')
    elif (
        int(resp.getlayer(ICMP).type)==3 and
        int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
    ):
        print(host, 'is blocking ICMP.')
    else:
        print(host, 'is responding.')
        liveCounter += 1

print('{}/{} hosts are online.'.format(liveCounter, addresses.size))
