#!/usr/bin/env python

from __future__ import print_function
from scapy.all import *
# from scipy.misc import imsave
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

# DEBUG = True
DEBUG = False

PROCESSED_HOSTS = {}

def h_name(host_addr):
    if host_addr in PROCESSED_HOSTS:
        return PROCESSED_HOSTS[host_addr]
    else:
        hn = "h" + str(len(PROCESSED_HOSTS))
        PROCESSED_HOSTS[host_addr] = hn

        return hn

def h_index(host_name):
    return int(re.sub("[^\d.]+", "", host_name))

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

        elif 'IPv6' in p:
            h_src = h_name(p[IPv6].src)
            h_dst = h_name(p[IPv6].dst)

            if 'TCP' in p:
                teste = "TCP {}:%r,TCP.sport% > {}:%r,TCP.dport%".format(h_src, h_dst)
                sess = p.sprintf(teste)
            elif 'UDP' in p:
                teste = "UDP {}:%r,UDP.sport% > {}:%r,UDP.dport%".format(h_src, h_dst)
                sess = p.sprintf(teste)
            elif 'ICMP' in p:
                sess = p.sprintf("ICMP %IPv6.src% > %IPv6.dst% type=%r,ICMP.type% code=%r,ICMP.code% id=%ICMP.id%")
            else:
                sess = p.sprintf("IPv6 %IPv6.src% > %IPv6.dst% proto=%IPv6.proto%")

        elif 'ARP' in p:
            sess = p.sprintf("ARP %ARP.psrc% > %ARP.pdst%")
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess

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
                else:
                    # add new dst entry
                    pkts_statistics[src][dst] = {
                        'len': int(pkt[IP].len),
                        'proto': pkt[IP].proto,
                        'packets': 1
                    }
            else:
                # add new OD entry
                pkts_statistics[src] = {
                    dst: {
                        'len': int(pkt[IP].len),
                        'proto': pkt[IP].proto,
                        'packets': 1
                    }
                }

        except Exception as e:
            pp.pprint("Something rot dissecting IP: {} for pkt {}".format(e, pkt.show()))

    elif pkt.haslayer(ARP):
        try:
            src = h_name(pkt[ARP].psrc)
            dst = h_name(pkt[ARP].pdst)

            if DEBUG:
                pp.pprint("from {} to {}, details: {}".format(src, dst, len(pkt[ARP])))

            if src in pkts_statistics:
                # already added
                if dst in pkts_statistics[src]:
                    pkts_statistics[src][dst]['len'] += int(len(pkt[ARP]))
                    pkts_statistics[src][dst]['packets'] += 1
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
            pp.pprint("Something rot dissecting ARP {}".format(e))

def paint(proto, count):
    a = count << 4
    a = a | proto
    return a

def build_traffic_matrix(pkts_statistics):
    n = len(PROCESSED_HOSTS)

    if DEBUG:
        pp.pprint("New matrix with {} x {}".format(n,n))

    tf = np.zeros((n,n), dtype=np.uint32)
    # tf.fill(0xFFFFFFFF)
    # tfd = np.zeros((n,n), dtype=object)

    for k, v in pkts_statistics.items():
        if DEBUG: print("Processing {}".format(k))
        hi1 = h_index(k)

        for sk, sv in v.items():
            if DEBUG: print("-- sub processing {}".format(sk))
            hi2 = h_index(sk)

            try:
                # tf[hi1][hi2] = sv['len']
                tf[hi1][hi2] = paint(sv['proto'], sv['len'])
                # tfd[hi1][hi2] = sv #['len']
            except Exception as e:
                pp.pprint("Something rot build TF {}".format(e))

    # TFS_PROCESSED.append(tf)
    # TFS_PROCESSED_DUP.append(tfd)
    return tf

def do_magic(pcap_file):
    pkts_statistics = {}

    p = rdpcap(pcap_file)

    sessions = p.sessions(session_extractor)

    if DEBUG:
        pp.pprint(sessions)

    for session in sessions:
        for packet in sessions[session]:
            dissect_packet(packet, pkts_statistics)

    tfs = build_traffic_matrix(pkts_statistics)

    plot_things(os.path.basename(pcap_file), tfs)

def h_entries():
    return list(PROCESSED_HOSTS.values())

def plot_things(filename, matrix):
    H = matrix
    shape = (H.shape)[0]
    # H1 = TFS_PROCESSED_DUP[index]

    hs = h_entries()

    # plt.imshow(H, cmap='gray', interpolation='none')
    # # plt.show()
    # # heatmap = plt.pcolor(H, cmap='gray', interpolation='none')

    # # for y in range(H.shape[0]):
    # #     for x in range(H.shape[1]):
    #         plt.text(x + 0.5, y + 0.5, str(H1[y, x]),
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

    # ax.set_xticklabels(['']+hs)
    # ax.set_yticklabels(['']+hs)

    if DEBUG:
        plt.savefig("../figs/DEBUG-FIG-{}.png".format(filename), bbox_inches=None)
        plt.show()
    else:
        plt.savefig("../figs/OD-{}.png".format(filename), bbox_inches='tight')
    # imsave("../figs/OD-{}_bitmap.png".format(filename), H)

    plt.close('all')

pp = pprint.PrettyPrinter(indent=1)

if DEBUG:
    one_filename = '../../Pcaps/118-dump.pcap'
    do_magic(one_filename)
else:
    path = '../../Pcaps'

    for filename in glob.glob(os.path.join(path, '*.pcap')):

        pp.pprint("Reading {}".format(filename))

        try:
            do_magic(filename)

        except Exception as e:
            pp.pprint("Something rot there {}".format(e))

        finally:
            PROCESSED_HOSTS.clear()


