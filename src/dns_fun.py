from __future__ import print_function
from scapy.all import *

# answer = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='www.thepacketgeek.com')), verbose=0)

# print(answer)

dns_server_ip = '200.175.89.139'
bpf_filt = 'udp dst port 53 and ip dst {0}'.format(dns_server_ip)

def dns_responder(local_ip):

    def forward_dns(orig_pkt):
        print('Forwarding:', orig_pkt[DNSQR].qname)
        response = sr1(IP(dst='8.8.8.8')/UDP(sport=orig_pkt[UDP].sport)/DNS(rd=1,id=orig_pkt[DNS].id,qd=DNSQR(qname=orig_pkt[DNSQR].qname)), verbose=0)
        respPkt = IP(dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
        respPkt[DNS] = response[DNS]
        send(respPkt, verbose=0)
        return 'Responding: {}'.format(respPkt.summary())

    def get_response(pkt):
        if (
            DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0 and
            pkt[IP].src != local_ip
        ):
            if 'trailers.apple.com' in str(pkt['DNS Question Record'].qname):
                spfResp = IP(dst=pkt[IP].src)\
                    /UDP(dport=pkt[UDP].sport, sport=53)\
                    /DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip)\
                    /DNSRR(rrname='trailers.apple.com',rdata=local_ip))
                send(spfResp, verbose=0)
                return 'Spoofed DNS Response Sent'

            else:
                # make DNS query, capturing the answer and send the answer
                return forward_dns(pkt)

    return get_response

sniff(filter=bpf_filt, prn=dns_responder(dns_server_ip))
