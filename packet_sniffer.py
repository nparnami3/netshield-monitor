
import scapy.all as scapy # type: ignore
from scapy.layers.http import HTTPRequest # type: ignore

def packet_callback(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        packet_info = f"[+] HTTP Request: {method} {url}"
        return packet_info
    return None

def start_sniffing(interface, callback):
    def sniff_callback(packet):
        packet_info = packet_callback(packet)
        if packet_info:
            callback(packet_info)
    
    scapy.sniff(iface=interface, filter="tcp port 80", prn=sniff_callback, store=False)