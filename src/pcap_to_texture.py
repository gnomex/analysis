#!/usr/bin/env python

from scapy.all import *
import sys
import glob
import numpy as np
from PIL import Image

def do_magic(filename):
    DUMP = []
    packets = rdpcap(filename)
    # sessions = packets.sessions()

    print("get packets")

    for packet in packets:
        byte_array = list(map(ord, str(packet))) # list of numbers, such as [0xDE, 0xAD, 0xBE, 0xEF]
        DUMP.append(byte_array)

        print("dumped")
    # for session in sessions:
    #     for packet in sessions[session]:
    #         byte_array = list(map(ord, str(packet))) # list of numbers, such as [0xDE, 0xAD, 0xBE, 0xEF]
    #         DUMP.append(byte_array)

    flattened = [item for items in DUMP for item in items]

    # shape nrows x 32
    n = int(len(flattened)/32) + 1
    tf = np.zeros((n,32), dtype=np.uint32)

    i = 0
    j = 0
    for item in flattened:
        tf[i,j] = item

        if j < 31:
            j +=1
        else:
            j = 0
            i += 1

    print("imagifying")
    # print(tf.shape)
    img = Image.fromarray(tf, 'RGB')
    w, h = img.size
    scale_by = 1
    print("W {} and h {}".format(w, h))

    newsize = (w * scale_by, h * scale_by)
    img = img.resize(newsize)
    img.save("../dump_as_imgs/pd-{}.png".format(os.path.basename(filename)))

# file = '../../Pcaps/arp-storm.pcap'
# do_magic(file)

path = '../../kenner-pcaps'

for filename in glob.glob(os.path.join(path, '*.pcap')):

    print("Reading {}".format(filename))

    try:
        do_magic(filename)

    except Exception as e:
        pp.pprint("Something rot there {}".format(e))


