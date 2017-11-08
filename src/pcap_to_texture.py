#!/usr/bin/env python

from scapy.all import *
import sys
import glob
import numpy as np
from PIL import Image

def do_magic(img_path, filename):
    DUMP = []
    packets = rdpcap(filename)
    # sessions = packets.sessions()

    # avoid empty pcap
    if len(packets) < 1:
        return

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
    # tf = np.zeros((n,32), dtype=np.uint8)
    tf = np.zeros((n,32), dtype=np.uint8)

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
    # img = Image.fromarray(tf, mode='RGB')
    # img = Image.fromarray(tf)
    # 1 (1-bit pixels, black and white, stored with one pixel per byte)
    # L (8-bit pixels, black and white)
    # P (8-bit pixels, mapped to any other mode using a color palette)
    # RGB (3x8-bit pixels, true color)
    # RGBA (4x8-bit pixels, true color with transparency mask)
    # CMYK (4x8-bit pixels, color separation)
    # YCbCr (3x8-bit pixels, color video format)
    # LAB (3x8-bit pixels, the L*a*b color space)
    # HSV (3x8-bit pixels, Hue, Saturation, Value color space)
    # I (32-bit signed integer pixels)
    # F (32-bit floating point pixels)

    try:
        # img = Image.fromarray(tf, mode='P')
        img = Image.fromarray(tf, mode='L')
        # img = Image.fromarray(tf, mode='RGB')
        w, h = img.size
        scale_by = 10

        if h > 10000:
            scale_by = 1

        print("W {} and h {}".format(w, h))

        newsize = (w * scale_by, h * scale_by)
        img = img.resize(newsize)
        # img.save("../dump_as_imgs/pd-{}.png".format(os.path.basename(filename)))
        img.save("{}/pd-{}.jpg".format(img_path, os.path.basename(filename)), format='JPEG', subsampling=0, quality=100)
    except Exception as e:
        print("Something rot there {}, file {}".format(e, filename))

# file = '../../Pcaps/arp-storm.pcap'
# do_magic(file)

path = '../../Pcaps'
img_path = '../good_pcaps'

# path = '../../kenner-pcaps'
# img_path = '../bad_pcaps'

for filename in glob.glob(os.path.join(path, '*.pcap')):

    print("Reading {}".format(filename))

    try:
        do_magic(img_path, filename)

    except Exception as e:
        print("Something rot there {}, file {}".format(e, filename))
