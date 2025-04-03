#!/usr/bin/env python3

from random import randint
from scapy.all import IP, TCP, send

# scapy takes TCP flags: FSRPAUECN
XMAS = "FPU"
NULL = ""
SYN = "S"
FIN = "F"


# generate source IP in 10.10.octet.x/24
def gen_src_ip():
    return f"10.10.{randint(0, 255)}.{randint(0, 255)}"


# NOTE: [p1, p2, p3, ...] for discrete, (start, end) for continuous
def gen_packets(src_ip, target, flags, ports):
    ip_layer = IP(src=src_ip, dst=target)

    tcp_layer = TCP(sport=randint(1, 65535), dport=ports, flags=flags)
    packet = ip_layer/tcp_layer

    try:
        send(packet, verbose=False)
        print(f"{src_ip} -> {target}, ports: {ports}")
    except PermissionError:
        print("error: you must be root!")
        exit(1)


if __name__ == '__main__':
    gen_packets("10.10.66.66", "192.168.1.108", XMAS, [1, 1024])
