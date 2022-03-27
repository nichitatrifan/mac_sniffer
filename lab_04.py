#!/usr/bin/env python3
import scapy.all as scapy

from sys import argv

def main(filename:str):
    packet_list = scapy.rdpcap(filename) # getting the list of all packets in .pcap
    packet_list.summary(lambda x:x.show())
    
if __name__ == '__main__':
    if len(argv) < 2:
        print("Enter a filename!")

    print("Filename supplied :: ", argv[1])
    main(argv[1])
    
