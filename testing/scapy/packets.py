#!/usr/bin/env python3

from random import randint
from scapy.all import IP, TCP, send

# scapy takes TCP flags: FSRPAUECN
XMAS = "FPU"
NULL = ""
SYN = "S"
FIN = "F"

VERBOSE = True
QUIET = False


# generate source IP in 10.10.octet.x/24
def rand_ip(octet=""):
    if not octet:
        return f"10.10.{randint(0, 255)}.{randint(0, 255)}"
    return f"10.10.{octet}.{randint(0, 255)}"


def rand_port():
    return randint(0, 65535)


# NOTE: [p1, p2, p3, ...] for discrete, (start, end) for continuous
def gen_packets(src_ip, target, flags, ports, log_level=QUIET):
    ip_layer = IP(src=src_ip, dst=target)

    tcp_layer = TCP(sport=rand_port(), dport=ports, flags=flags)
    packet = ip_layer / tcp_layer

    try:
        send(packet, verbose=log_level)
    except PermissionError as e:
        print(f"error sending packets: {e}")
        exit(1)
