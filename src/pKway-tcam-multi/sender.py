#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, XShortField, BitField
from scapy.all import bind_layers
import readline

class P4kway(Packet):
    name = "p4kway"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("front_type", "F", length=1),
                    StrFixedLenField("main_type", "F", length=1),
                    BitField("k", 0, 16),
                    XShortField("v", 0),
                    BitField("cache", 0, 8),
                    BitField("front", 0, 8),
                    ]


bind_layers(Ether, P4kway, type=0x1234)


def main():
    s = ''
    iface = 'eth0'

    while s not in ['LFU', 'FIFO']:
        s = str(raw_input('Type FIFO or LFU for FRONT > '))
    if s == 'LFU':
        t1 = 'F'
    elif s == 'FIFO':
        t1 = 'R'
    
    s = ''
    while s not in ['LFU', 'FIFO']:
        s = str(raw_input('Type FIFO or LFU for MAIN > '))
    if s == 'LFU':
        t2 = 'F'
    elif s == 'FIFO':
        t2 = 'R'

    while True:
        s = str(raw_input('Type a key or quit or exit> '))
        if s == "quit":
            break
        if s == "exit":
            break
        s = int(s)

        print s
        try:
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4kway(front_type=t1, main_type=t2, k=s)
            pkt = pkt/' '

#            pkt.show()
            resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            if resp:
                p4kway=resp[P4kway]
                if p4kway:
                    print('key={}, value={}, from_cache={}, from_front={}'.format(p4kway.k, p4kway.v, p4kway.cache, p4kway.front))
                else:
                    print "cannot find P4aggregate header in the packet"
            else:
                print "Didn't receive response"
        except Exception as error:
            print 'error --> ' + error.message


if __name__ == '__main__':
    main()
