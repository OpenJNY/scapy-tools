from scapy.all import *
from datetime import datetime
import socket
import struct
import ipaddress

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

class FiveTuple(object):    
    def __init__(self, p):
        if not isinstance(p, scapy.packet.Packet):
            raise ValueError(f'Ihis is not an instance of scapy packet')
        if not is_tcp(p) and not is_udp(p):
            raise VlueError(f'This is a neither TCP nor UDP packet.')
        
        h1, h1_p, h2, h2_p, proto = ip2int(p[IP].src), p[IP].sport, ip2int(p[IP].dst), p[IP].dport, p.proto
        if h1 < h2:
            h1, h1_p, h2, h2_p, proto = h2, h2_p, h1, h1_p, proto
        self.h1, self.h1_p, self.h2, self.h2_p, self.proto = h1, h1_p, h2, h2_p, proto
        
    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (self.h1 == other.h1) and (self.h2 == other.h2) and (self.h1_p == other.h1_p) and (self.h2_p == other.h2_p) and (self.proto == other.proto)

    def __hash__(self):
        return hash((self.h1, self.h1_p, self.h2, self.h2_p, self.proto))
    
    def __str__(self):
        return f'({int2ip(self.h1)}, {self.h1_p}, {int2ip(self.h2)}, {self.h2_p}, {self.proto})'
    
    def matches(self, p):
        try:
            return self.__eq__(FiveTuple(p))
        except:
            return False

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def is_tcp_syn(x):
    return is_tcp(x) and (x[TCP].flags & SYN) and not (x[TCP].flags & ACK)

def is_tcp_synack(x):
    return is_tcp(x) and (x[TCP].flags & SYN) and (x[TCP].flags & ACK)

def is_tcp_ack(x):
    return is_tcp(x) and not (x[TCP].flags & SYN) and (x[TCP].flags & ACK)

def is_tcp(x):
    return x.haslayer(TCP)

def is_udp(x):
    return x.haslayer(UDP)

def communicates_with_global_endpoints(p):
    if IP in p:
        # https://docs.python.org/ja/3/library/ipaddress.html#ipaddress.IPv4Address.is_global
        return ipaddress.IPv4Address(p[IP].src).is_global or ipaddress.IPv4Address(p[IP].dst).is_global
    return False

def communicates_with(p, ip_address):
    if IP in p:
        return ip_address in (p[IP].src, p[IP].dst)
    return False
