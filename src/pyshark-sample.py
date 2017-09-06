#!/usr/bin/env python

import syslog
import os
import signal
import sys
import click
from datetime import datetime

import pyshark

excluded_protocols = {}
excluded_protocols_file = 'excluded_protocols.list'

# Get supported application protocols
def get_excluded_protocols():
    global excluded_protocols
    global excluded_protocols_file
    fp = None
    if os.path.isfile(excluded_protocols_file):
        fp = open(excluded_protocols_file)
    elif os.path.isfile('../conf/'+excluded_protocols_file):
        fp = open('../conf/'+excluded_protocols_file)
    elif os.path.isfile('conf/'+excluded_protocols_file):
        fp = open('conf/'+excluded_protocols_file)
    protocols = fp.readlines()
    for protocol in protocols:
        protocol = protocol.strip()
        excluded_protocols[protocol] = 1

# Get application level protocol
def get_highest_protocol(packet):
    global excluded_protocols
    if not excluded_protocols:
        get_excluded_protocols()
    for layer in reversed(packet.layers):
        if layer.layer_name in excluded_protocols:
            continue
        else:
            return str.replace(layer.layer_name, '.', '-')

# Get the protocol layer fields
def get_layer_fields(layer):
    layer_fields = {}
    for field_name in layer.field_names:
        if len(field_name) > 0:
            layer_fields[field_name] = getattr(layer, field_name)
    return layer_fields

# Returns a dictionary containing the packet layer data
def get_layers(packet):
    n = len(packet.layers)
    highest_protocol = get_highest_protocol(packet)
    layers = {}

    # Link layer
    layers[packet.layers[0].layer_name] = get_layer_fields(packet.layers[0])
    layers[packet.layers[0].layer_name]['level'] = 0
    layer_above_transport = 0

    # Get the rest of the layers
    for i in range(1,n):
        layer = packet.layers[i]

        # Network layer - ARP
        if layer.layer_name == 'arp':
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[layer.layer_name]['level'] = i
            return highest_protocol, layers

        # Network layer - IP or IPv6
        elif layer.layer_name == 'ip' or layer.layer_name == 'ipv6':
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[layer.layer_name]['level'] = i

        # Transport layer - TCP, UDP, ICMP, IGMP, IDMP, or ESP
        elif layer.layer_name == 'tcp' or layer.layer_name == 'udp' or layer.layer_name == 'icmp' or layer.layer_name == 'igmp' or layer.layer_name == 'idmp' or layer.layer_name == 'esp':
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[layer.layer_name]['level'] = i
            if highest_protocol == 'tcp' or highest_protocol == 'udp' or highest_protocol == 'icmp' or highest_protocol == 'esp':
                return highest_protocol, layers
            layer_above_transport = i+1
            break

        # Additional layers
        else:
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[layer.layer_name]['level'] = i

    for j in range(layer_above_transport,n):
        layer = packet.layers[j]

        # Application layer
        if layer.layer_name == highest_protocol:
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[layer.layer_name]['level'] = i

        # Additional application layer data
        else:
            layer_name = str.replace(layer.layer_name, '.', '-')
            if layer_name == '_ws-malformed':
                layer_name = '[Malformed_Packet]'
            layers[layer_name] = get_layer_fields(layer)
            layers[layer_name]['level'] = i

    return highest_protocol, layers

# Index packets in Elasticsearch
def index_packets(capture, pcap_file, file_date_utc, count):
    pkt_no = 1
    for packet in capture:
        highest_protocol, layers = get_layers(packet)
        sniff_timestamp = float(packet.sniff_timestamp) # use this field for ordering the packets in ES
        if pcap_file == None:
            action = {
                '_op_type' : 'index',
                '_index' : 'packets-'+datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%d'),
                '_type' : 'pcap_live',
                '_source' : {
                    'sniff_date_utc' : datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%dT%H:%M:%S+0000'),
                    'sniff_timestamp' : sniff_timestamp,
                    'protocol' : highest_protocol,
                    'layers' : layers
                }
            }
            yield action
        else:
            action = {
                '_op_type' : 'index',
                '_index' : 'packets-'+datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%d'),
                '_type' : 'pcap_file',
                '_source' : {
                    'file_name' : pcap_file,
                    'file_date_utc' : file_date_utc.strftime('%Y-%m-%dT%H:%M:%S'),
                    'sniff_date_utc' : datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%dT%H:%M:%S+0000'),
                    'sniff_timestamp' : sniff_timestamp,
                    'protocol' : highest_protocol,
                    'layers' : layers
                }
            }
            yield action
        pkt_no += 1
        if count > 0 and pkt_no > count:
            return

# Dump raw packets to stdout
def dump_packets(capture, file_date_utc, count):
    pkt_no = 1
    for packet in capture:
        highest_protocol, layers = get_layers(packet)
        sniff_timestamp = float(packet.sniff_timestamp)
        print 'Packet no.', pkt_no
        print '* protocol        -', highest_protocol
        print '* file date UTC   -', file_date_utc.strftime('%Y-%m-%dT%H:%M:%S+0000')
        print '* sniff date UTC  -', datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%dT%H:%M:%S+0000')
        print '* sniff timestamp -', sniff_timestamp
        print '* layers'
        for key in layers:
            print '\t', key, layers[key]
        print
        pkt_no += 1
        if count > 0 and pkt_no > count:
            return

# Live capture function
def live_capture(nic, bpf, node, chunk, count):
    try:
        es = None
        if (node != None):
            es = Elasticsearch(node)

        sniff_date_utc = datetime.utcnow()
        if bpf == None:
            capture = pyshark.LiveCapture(interface=nic)
        else:
            capture = pyshark.LiveCapture(interface=nic, bpf_filter=bpf)

        # Dump or index packets based on whether an Elasticsearch node is available
        if node == None:
            dump_packets(capture, sniff_date_utc, count)
        else:
            helpers.bulk(es, index_packets(capture, None, sniff_date_utc, count), chunk_size=chunk, raise_on_error=True)

    except Exception as e:
        print '[ERROR] ', e
        syslog.syslog(syslog.LOG_ERR, e.message)

# File capture function
def file_capture(pcap_files, node, chunk):
    try:
        es = None
        if node != None:
            es = Elasticsearch(node)

        print 'Loading packet capture file(s)'
        for pcap_file in pcap_files:
            print pcap_file
            stats = os.stat(pcap_file)
            file_date_utc = datetime.utcfromtimestamp(stats.st_ctime)
            capture = pyshark.FileCapture(pcap_file)

            # If no Elasticsearch node specified, dump to stdout
            if node == None:
                dump_packets(capture, file_date_utc, 0)
            else:
                helpers.bulk(es, index_packets(capture, pcap_file, file_date_utc, 0), chunk_size=chunk, raise_on_error=True)

    except Exception as e:
        print '[ERROR] ', e
        syslog.syslog(syslog.LOG_ERR, e.message)


# Returns list of network interfaces (nic)
def list_interfaces():
    proc = os.popen('tshark -D')  # Note tshark must be in $PATH
    tshark_out = proc.read()
    interfaces = tshark_out.splitlines()
    for i in range(len(interfaces)):
        interface = interfaces[i].strip(str(i+1)+'.')
        print interface

def interrupt_handler(signum, frame):
    print
    print('Packet capture interrupted')
    print 'Done'
    sys.exit()

@click.command()
@click.option('--node', default=None, help='Elasticsearch IP and port (default=None, dump packets to stdout)')
@click.option('--nic', default=None, help='Network interface for live capture (default=None, if file or dir specified)')
@click.option('--file', default=None, help='PCAP file for file capture (default=None, if nic specified)')
@click.option('--dir', default=None, help='PCAP directory for multiple file capture (default=None, if nic specified)')
@click.option('--bpf', default=None, help='Packet filter for live capture (default=all packets)')
@click.option('--chunk', default=1000, help='Number of packets to bulk index (default=1000)')
@click.option('--count', default=0, help='Number of packets to capture during live capture (default=0, capture indefinitely)')
@click.option('--list', is_flag=True, help='List the network interfaces')
def main(node, nic, file, dir, bpf, chunk, count, list):
    if list:
        list_interfaces()
        sys.exit(0)

    if nic == None and file == None and dir == None:
        print 'You must specify either file or live capture'
        sys.exit(1)

    syslog.syslog("espcap started")
    signal.signal(signal.SIGINT, interrupt_handler)

    if nic != None:
        live_capture(nic, bpf, node, chunk, count)

    elif file != None:
        pcap_files = []
        pcap_files.append(file)
        file_capture(pcap_files, node, chunk)

    elif dir != None:
        pcap_files = []
        files = os.listdir(dir)
        files.sort()
        for file in files:
            if dir.find('/') > 0:
                pcap_files.append(dir+file)
            else:
                pcap_files.append(dir+'/'+file)
        file_capture(pcap_files, node, chunk)

if __name__ == '__main__':
    main()
    print 'Done'
