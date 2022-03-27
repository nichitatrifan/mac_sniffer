#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.l2 import *

from sys import argv

def main(filename:str):
    packet_list = rdpcap(filename)
    # packet_list.summary(lambda x:x.show())

    print(packet_list, end='\n\n')

    arp_request = packet_list[0]
    arp_request.show()

    print('---------------------------------------------\n')

    ether_fields = {
        'dst': arp_request.src,
        'src': '00:0c:29:c5:33:72'
    }

    arp_fields = {
        'hwtype': 1,
        'ptype': 4,
        'hwlen': 6,
        'plen': 4,
        'op': 2,
        'hwsrc': '00:0c:29:c5:33:72',
        'psrc': arp_request.pdst,
        'hwdst': arp_request.src,
        'pdst': arp_request.psrc
    }
    
    #arp_response = Packet.copy(arp_request)
    arp_response = Ether()/ARP()

    arp_response[Ether].dst = arp_request.src
    arp_response[Ether].src = '00:0c:29:c5:33:72'
    arp_response[Ether].type = 'ARP'

    arp_response[ARP].hwtype = arp_request.hwtype
    arp_response[ARP].ptype = arp_request.ptype
    arp_response[ARP].hwlen = arp_request.hwlen
    arp_response[ARP].plen = arp_request.plen
    arp_response[ARP].op = 2
    arp_response[ARP].hwsrc = '00:0c:29:c5:33:72'
    arp_response[ARP].psrc =  arp_request.pdst
    arp_response[ARP].hwdst = arp_request.src
    arp_response[ARP].pdst = arp_request.psrc

    arp_response.show()

if __name__ == '__main__':
    if len(argv) < 2:
        print("Enter a filename!")

    print("Filename supplied :: ", argv[1])
    main(argv[1])
