#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, get_if_list# , sendp, hexdump, get_if_hwaddr
from scapy.all import Packet# , IPOption
from scapy.all import PacketListField, IntField, BitField #, ShortField, LongField, FieldListField, FieldLenField
from scapy.all import TCP, IP#, UDP, Raw
from scapy.all import bind_layers
# from scapy.layers.inet import _IPOption_HDR

TYPE_INT = 0x12
TYPE_TCP = 0x06


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

"""
class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
"""

class IntFilho(Packet):
    name = "INT Filho"
    fields_desc = [ 
        IntField("id_switch", 0),
        BitField("porta_entrada", 0, 9),
        BitField("porta_saida", 0, 9),
        BitField("timestamp", 0, 48),
        BitField("type", 0, 8),
        BitField("padding", 0, 6)
    ]

class IntPai(Packet):
    name = "INT Pai"
    fields_desc = [ 
        IntField("tam_filho", -1),
        IntField("qtd_filhos", -1),
        PacketListField("int_filhos", None, IntFilho, count_from = lambda pkt : pkt.qtd_filhos)
    ]

def handle_pkt(pkt):
    if IntPai in pkt:
        pkt.show2()
    # if TCP in pkt and pkt[TCP].dport == 1234:
    #     print "got a packet"
    #     pkt.show2()
    # #    hexdump(pkt)
    #     sys.stdout.flush()


if __name__ == '__main__':
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    
    bind_layers(IP, IntPai, proto=TYPE_INT) # Basic tunnelling example
    bind_layers(IntPai, TCP, next_proto=TYPE_TCP) # Basic tunnelling example
    
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
