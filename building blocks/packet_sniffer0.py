#To check packets data in terminal
#!usr/bin/env python
import scapy.all as scapy
#interface got by ifconfig command,prn takes function which would be execute
def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=process_sniff_packet)

def process_sniff_packet(packet):
    print(packet.show())


sniff("wlan0")