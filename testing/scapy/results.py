#!/usr/bin/env python3

import bpfmaps
import socket
from enum import Enum
from colorama import Fore, Style


class xdp_action(Enum):
    XDP_ABORTED = 0
    XDP_DROP = 1
    XDP_PASS = 2
    XDP_TX = 3
    XDP_REDIRECT = 4


def lookup(map_name, ip):
    try:
        map = bpfmaps.BPF_Map.get_map_by_name(map_name)
        key = int.from_bytes(socket.inet_pton(socket.AF_INET, ip), "little")
        # print(f"looking up BPF {map_name}[{key}]...")
        result = map[key]
    except AssertionError as e:
        print(f"{Fore.RED + "BPF map error:" + Fore.RESET} {e}")
        result = None

    return result


def print_xdp_result(test_name, real, expected):
    real = xdp_action(real)
    if real == expected:
        print(
            f"{Fore.BLUE + test_name}: "
            f"{Fore.YELLOW + real.name + Fore.RESET}"
            f" -> {Fore.GREEN + 'pass'}"
        )
    else:
        print(
            f"{Fore.BLUE + test_name}: "
            f"{Fore.YELLOW + real.name + Fore.RESET}"
            f" -> {Fore.RED + 'fail'}"
        )

    print(Style.RESET_ALL)
