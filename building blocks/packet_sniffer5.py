#To check packets data in terminal in http protocol not on httpS
#!usr/bin/env python
import scapy.all as scapy
from scapy.layers.http import HTTPRequest

#interface got by ifconfig command,prn takes function which would be execute
def sniff(interface):
    # scapy.sniff(iface=interface, store=False,prn=process_sniff_packet, filter="port 21")
    # scapy.sniff(iface=interface, store=False,prn=process_sniff_packet, filter="tcp")
    scapy.sniff(iface=interface, store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        # print(packet[HTTPRequest].Path)
        url = packet[HTTPRequest].Host + packet[HTTPRequest].Path
        print(url)

sniff("wlp1s0")