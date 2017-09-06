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

DEBUG = True
# DEBUG = False

PKTS_TOTAL=0
HTTP_PKTS=0
TFS_PROCESSED = []
TFS_PROCESSED_DUP = []
HOSTS = {}

def session_extractor(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            h_src = h_name(p[IP].src)
            h_dst = h_name(p[IP].dst)

            if 'TCP' in p:
                teste = "TCP {}:%r,TCP.sport% > {}:%r,TCP.dport%".format(h_src, h_dst)
                sess = p.sprintf(teste)
            elif 'UDP' in p:
                teste = "UDP {}:%r,UDP.sport% > {}:%r,UDP.dport%".format(h_src, h_dst)
                sess = p.sprintf(teste)
            elif 'ICMP' in p:
                sess = p.sprintf("ICMP %IP.src% > %IP.dst% type=%r,ICMP.type% code=%r,ICMP.code% id=%ICMP.id%")
            else:
                sess = p.sprintf("IP %IP.src% > %IP.dst% proto=%IP.proto%")
        elif 'ARP' in p:
            sess = p.sprintf("ARP %ARP.psrc% > %ARP.pdst%")
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess

def interesting(packet):
    def expand(x):
        yield x
        while x.payload:
            x = x.payload
            yield x

    res = list(expand(packet))

def h_name(host_addr):
    if host_addr in HOSTS:
        return HOSTS[host_addr]
    else:
        hn = "h" + str(len(HOSTS))
        HOSTS[host_addr] = hn

        return hn

def h_index(h_name):
    return int(re.sub("[^\d.]+", "", h_name))

def do_magic(pcap_file):
    global PKTS_TOTAL
    global HTTP_PKTS

    pkts_statistics = {}

    p = rdpcap(pcap_file)

    sessions = p.sessions(session_extractor)

    if DEBUG:
        pp.pprint(sessions)

    for session in sessions:
        for packet in sessions[session]:
            PKTS_TOTAL += 1

            if packet.haslayer('HTTP'):
                HTTP_PKTS += 1

            dissect_packet(packet, pkts_statistics)

    build_traffic_matrix(pkts_statistics)

def dissect_packet(pkt, pkts_statistics):

    if pkt.haslayer(IP):
        try:
            # src = pkt[IP].src
            # dst = pkt[IP].dst
            src = h_name(pkt[IP].src)
            dst = h_name(pkt[IP].dst)

            if src in pkts_statistics:
                # already added
                if dst in pkts_statistics[src]:

                    pkts_statistics[src][dst]['len'] += int(pkt[IP].len)
                    pkts_statistics[src][dst]['packets'] += 1
                    # handle different protos: ARP, ICMP, TCP, UDP

                else:
                    # add new dst entry
                    pkts_statistics[src][dst] = {
                        'len': pkt[IP].len,
                        'proto': pkt[IP].proto,
                        'packets': 1
                    }

            else:
                # add new OD entry
                pkts_statistics[src] = {
                    dst: {
                        'len': pkt[IP].len,
                        'proto': pkt[IP].proto,
                        'packets': 1
                    }
                }

        except Exception as e:
            print(e)
    elif pkt.haslayer(ARP):
        try:
            src = h_name(pkt[ARP].psrc)
            dst = h_name(pkt[ARP].pdst)

            pp.pprint("from {} to {}, details: {}".format(src, dst, len(pkt[ARP])))

            if src in pkts_statistics:
                # already added
                if dst in pkts_statistics[src]:

                    pkts_statistics[src][dst]['len'] += int(len(pkt[ARP]))
                    pkts_statistics[src][dst]['packets'] += 1
                    # handle different protos: ARP, ICMP, TCP, UDP

                else:
                    # add new dst entry
                    pkts_statistics[src][dst] = {
                        'len': len(pkt[ARP]),
                        'proto': pkt[ARP].ptype,
                        'packets': 1
                    }

            else:
                # add new OD entry
                pkts_statistics[src] = {
                    dst: {
                        'len': len(pkt[ARP]),
                        'proto': pkt[ARP].ptype,
                        'packets': 1
                    }
                }

        except Exception as e:
            print(e)

def build_traffic_matrix(pkts_statistics):
    n = len(HOSTS)
    # tf = np.zeros((n,n), dtype=np.uint8)

    if DEBUG:
        pp.pprint("New matrix with {} x {}".format(n,n))

    tf = np.zeros((n,n), dtype=np.uint32)
    # tf.fill(0xFFFFFFFF)
    tfd = np.zeros((n,n), dtype=object)

    for k, v in pkts_statistics.items():
        if DEBUG: print("Processing {}".format(k))
        hi1 = h_index(k)

        for sk, sv in v.items():
            if DEBUG: print("-- sub processing {}".format(sk))
            hi2 = h_index(sk)

            try:
                tf[hi1][hi2] = sv['len']
                tfd[hi1][hi2] = sv #['len']
            except Exception as e:
                print(e)

    TFS_PROCESSED.append(tf)
    TFS_PROCESSED_DUP.append(tfd)

# def just_do_something(pcap_file):
    # with PcapReader(pcap_file) as pcap_reader:
        # for pkt in pcap_reader:
            # dissect_packet(pkt)

def h_entries():
    return list(HOSTS.values())

def plot_things(index):
    H = TFS_PROCESSED[index]
    H1 = TFS_PROCESSED_DUP[index]
    shape = (H.shape)[0]

    hs = h_entries()

    # plt.imshow(H, cmap='gray', interpolation='none')
    # # plt.show()
    # # heatmap = plt.pcolor(H, cmap='gray', interpolation='none')

    # # for y in range(H.shape[0]):
    # #     for x in range(H.shape[1]):
    # #         plt.text(x + 0.5, y + 0.5, str(H1[y, x]),
    # #                  horizontalalignment='center',
    # #                  verticalalignment='center',
    # #                  multialignment='center',
    # #                  )
    # plt.imshow(H, cmap='magma', interpolation='none')

    fig = plt.figure()
    ax = fig.add_subplot(1,1,1)

    # major ticks every 20, minor ticks every 5
    major_ticks = np.arange(0, shape, 1)
    minor_ticks = np.arange(0, shape, 1)

    ax.set_xticks(major_ticks)
    ax.set_xticks(minor_ticks, minor=True)
    ax.set_yticks(major_ticks)
    ax.set_yticks(minor_ticks, minor=True)

    # and a corresponding grid
    ax.grid(which='both')
    # or if you want differnet settings for the grids:
    ax.grid(which='minor', alpha=0.2)
    ax.grid(which='major', alpha=0.5)

    # ax.grid(True)
    # cax = ax.matshow(H, cmap='Greys', interpolation='nearest')
    cax = ax.matshow(H, cmap='GnBu', interpolation='nearest')
    fig.colorbar(cax)

    # ax.set_xticklabels([]+hs)
    # ax.set_yticklabels([]+hs)

    if DEBUG:
        plt.savefig("./figs/DEBUG-FIG-{}.png".format(index), bbox_inches=None)
        plt.show()
    else:
        plt.savefig("./figs/fig{}.png".format(index), bbox_inches='tight')
    # imsave("./figs/fig{}_bitmap.png".format(index), H)

    plt.close('all')

pp = pprint.PrettyPrinter(indent=1)
# print(dicttoxml.dicttoxml(pkt_analysis, attr_type=False))

if DEBUG:
    one_filename = '../../Pcaps/201709031400.pcap'
    do_magic(one_filename)
else:
    path = '../../Pcaps'
    # path = '../../pcaps-da-net'
    for filename in glob.glob(os.path.join(path, '*.pcap')):
        pp.pprint(filename)
        do_magic(filename)

if DEBUG:
    pp.pprint(TFS_PROCESSED)
    pp.pprint(TFS_PROCESSED_DUP)

print("Total of {} analyzed pkts and {} are HTTP ".format(PKTS_TOTAL, HTTP_PKTS))
print("Done, now I will show it!")

from scipy.misc import imsave

for index in range(0, len(TFS_PROCESSED)):
    plot_things(index)
