#!/usr/bin/env python

from __future__ import print_function
from scapy.all import *
import pprint
import sys
import glob
import dicttoxml
import re
import numpy as np
import matplotlib.pyplot as plt

try:
    import scapy_http.http
except ImportError:
    from scapy.layers import http

def interesting(packet):
    def expand(x):
        yield x
        while x.payload:
            x = x.payload
            yield x

    res = list(expand(packet))


# def just_do_something(pcap_file):
    # with PcapReader(pcap_file) as pcap_reader:
        # for pkt in pcap_reader:
            # dissect_packet(pkt)


def h_entries():
    return list(HOSTS.values())
