#!/usr/bin/env python3

from __future__ import print_function
import pprint
from scapy.all import *
from netaddr import *
import sys

pp = pprint.PrettyPrinter(indent=1)

pcap_file = sys.argv[1]

def print_summary(pkt):
    pp.pprint(pkt.summary())
    # if IP in pkt:
    #     ip_src=pkt[IP].src
    #     ip_dst=pkt[IP].dst
    # if TCP in pkt:
    #     tcp_sport=pkt[TCP].sport
    #     tcp_dport=pkt[TCP].dport

        # pp.pprint(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
        # pp.pprint(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))

def do_magic():

    p = rdpcap(pcap_file)

    sessions = p.sessions()

    # pp.pprint(sessions)

    for session in sessions:
        pp.pprint(session)
        # for packet in sessions[session]:
        #     print_summary(packet)

# pp.pprint(p.sessions())
do_magic()

