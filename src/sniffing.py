from scapy.all import *

pkts = sniff(count=1000)

# pkts.summary()

for packet in pkts:
    packet.show()
