#!/usr/bin/env python3

from __future__ import print_function
from scapy.all import *
from netaddr import *
import random

# Define IP range to scan
network = '192.168.1.0/24'
# Define TCP port range
portRange = [22,23,80,443,449]

# make list of addresses out of network, set live host counter
addresses = IPNetwork(network)
liveCounter = 0

def port_scan(host, ports):
    # Send SYN with random Src Port for each Dst port
    for dst_port in ports:
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host)/TCP(sport=src_port, dport=dst_port, flags='S'),
            timeout=1,
            verbose=0,
        )
        if resp is None:
            print('{}:{} is filtered (silently dropped).'.format(host, dst_port))
        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(
                    IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                    timeout=1,
                    verbose=0,
                )
                print('{}:{} is open.'.format(host, dst_port))
            elif (resp.getlayer(TCP).flags == 0x14):
                print('{}:{} is closed.'.format(host, dst_port))
            elif(resp.haslayer(ICMP)):
                if(
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
                ):
                    print('{}:{} is filtered (silently dropped).'.format(host, dst_port))

# Send ICMP ping request, wait for answer
for addr in addresses:
    if (addr == addresses.network or addr == addresses.broadcast):
        # Skip network and broadcast addresses
        continue

    resp = sr1(IP(dst=str(addr))/ICMP(), timeout=2, verbose=0)

    if resp is None:
        print(addr, ' is down or not responding.')
    elif (
        int(resp.getlayer(ICMP).type) == 3 and
        int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
    ):
        print(addr, ' is blocking ICMP.')
    else:
        port_scan(str(addr), portRange)
        liveCounter += 1

print('{}/{} hosts are online.'.format(liveCounter, addresses.size))
