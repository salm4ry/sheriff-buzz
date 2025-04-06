#!/usr/bin/env python3

from random import randint
from scapy.all import IP, TCP, send

# scapy takes TCP flags: FSRPAUECN
XMAS = "FPU"
NULL = ""
SYN = "S"
FIN = "F"


# generate source IP in 10.10.octet.x/24
def rand_src_ip(octet=""):
    if not octet:
        return f"10.10.{randint(0, 255)}.{randint(0, 255)}"
    return f"10.10.{octet}.{randint(0, 255)}"


def rand_port():
    return randint(0, 65535)


# NOTE: [p1, p2, p3, ...] for discrete, (start, end) for continuous
def gen_packets(src_ip, target, flags, ports, verbose=False):
    ip_layer = IP(src=src_ip, dst=target)

    tcp_layer = TCP(sport=rand_port(), dport=ports, flags=flags)
    packet = ip_layer / tcp_layer

    try:
        send(packet, verbose=verbose)
        # print(f"{src_ip} -> {target}, ports: {ports}")
    except PermissionError as e:
        print(e)
        exit(1)


if __name__ == "__main__":
    gen_packets("10.10.66.66", "192.168.1.108", XMAS, [1, 1024])
