from __future__ import print_function
from scapy.all import *

# print(sr1(IP(dst="4.2.2.1")/ICMP()).summary())

# pkts = sniff(filter="arp",count=10)
# print(pkts.summary())

def arp_display(pkt):
    if pkt[ARP].op == 1:  # who-has (request)
        return 'Request: {} is asking about {}'.format(pkt[ARP].psrc, pkt[ARP].pdst)
    if pkt[ARP].op == 2:  # is-at (response)
        return '*Response: {} has address {}'.format(pkt[ARP].hwsrc, pkt[ARP].psrc)

sniff(prn=arp_display, filter='arp', store=0, count=10)
