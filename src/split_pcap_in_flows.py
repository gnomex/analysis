#!/usr/bin/env python

from scapy.all import *
import sys
import glob
import numpy as np

def do_magic(filename, dst_path):
    packets = rdpcap(filename)
    sessions = packets.sessions()

    counter = 0

    # avoid empty pcap
    if len(packets) < 1:
        return

    for session in sessions:
        fname = "{}/{}-flow-{}".format( dst_path, os.path.basename(filename), counter)
        wrpcap( fname, sessions[session] )
        counter += 1
        print("just wrote {}".format(fname))

path = '/media/gnomex/zebras/kenner-pcaps'
dst_path = '/media/gnomex/zebras/kenner-pcap-flows'

for filename in glob.glob(os.path.join(path, '*.pcap')):
    print("Reading {}".format(filename))

    try:
        do_magic(filename, dst_path)

    except Exception as e:
        print("Something rot there {}, file {}".format(e, filename))
