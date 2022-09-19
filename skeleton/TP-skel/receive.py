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

TYPE_INT_PAI = 0x1212
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
    name = "int_filho"
    fields_desc = [ 
        IntField("ID_Switch", 0),
        BitField("Porta_Entrada", 0, 9),
        BitField("Porta_Saida", 0, 9),
        BitField("Timestamp", 0, 48),
        BitField("Padding", 0, 6)
    ]

class IntPai(Packet):
    name = "int_pai"
    fields_desc = [ 
        IntField("Tam_Filho", 0),
        IntField("Qtd_Filhos", 0),
        PacketListField("int_filhos", None, IntFilho, length_from = lambda pkt : pkt.Qtd_Filhos*pkt.Tam_Filho)
    ]

def handle_pkt(pkt):
    pkt.show2()
    # if TCP in pkt and pkt[TCP].dport == 1234:
    #     print "got a packet"
    #     pkt.show2()
    # #    hexdump(pkt)
    #     sys.stdout.flush()
    # if IntPai in pkt:
    #     pkt.show2()


if __name__ == '__main__':
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    
    bind_layers(IP, IntPai, proto=TYPE_INT_PAI) # Basic tunnelling example
    bind_layers(IntPai, TCP, proto=TYPE_TCP) # Basic tunnelling example
    
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
