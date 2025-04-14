#!./.venv/bin/python3

import argparse
from colorama import Fore, Style

import packets
import config
from results import lookup, print_xdp_result, xdp_action
from args import init_args

TARGET_CONFIG_PATH = "~/sheriff-buzz/config.json"
TEST_PORT = 12345
TEST_BPF_MAP = "test_results"


class UnitTest:
    def __init__(
        self,
        name,
        expected,
        config_file,
        src_ip="",
        octet="",
        scan=True,
        port=None,
        port_threshold=100,
    ):
        self.name = name  # test name (used in output)
        self.expected = expected  # expected return value
        self.config_file = config_file  # path to config file
        self.do_scan = scan  # do a port scan?
        self.port_threshold = port_threshold  # sheriff-buzz port threshold

        # source IP (leave empty for random)
        if not src_ip:
            self.src_ip = packets.rand_ip(octet)
        else:
            self.src_ip = src_ip

        if port:
            self.port = port
        else:
            self.port = None

    def port_scan(self, target, port_threshold):
        """Perform a port scan to go over the port threshold"""
        # scan first 100 ports
        print(f"sending {port_threshold} packets from {self.src_ip}"
              "...", end="")
        packets.gen_packets(
            self.src_ip, target, packets.SYN, (1, port_threshold),
            log_level=packets.QUIET
        )
        print("done")
        print(f"check {self.src_ip} is {self.name}ed")
        print(f"sending 1 packet from {self.src_ip}...", end="")
        # send another packet in order to observe XDP return value
        packets.gen_packets(self.src_ip, target, packets.SYN, [TEST_PORT],
                            log_level=packets.QUIET)
        print("done")

    def single_packet(self, target):
        """Send a single packet"""
        if self.port:
            port = self.port
        else:
            port = TEST_PORT

        print(f"sending 1 packet from {self.src_ip}... ", end="")
        packets.gen_packets(self.src_ip, target, packets.SYN, [port],
                            log_level=packets.QUIET)
        print("done")

    def run(self, target):
        print(f"running {Fore.BLUE + self.name + Fore.RESET}")
        config.copy(src_path=self.config_file, dst_path=TARGET_CONFIG_PATH)

        if self.do_scan:
            self.port_scan(target, self.port_threshold)
        else:
            self.single_packet(target)

        # check results
        res = lookup(TEST_BPF_MAP, self.src_ip)

        if res is not None:
            print_xdp_result("result", res, self.expected)
        else:
            print(f"{Fore.BLUE + self.name}:{Fore.RESET} {Fore.YELLOW}"
                  "failed to run")
            print(Style.RESET_ALL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    init_args(parser)
    args = parser.parse_args()

    tests = [
        UnitTest(
            name="block",
            expected=xdp_action.XDP_DROP,
            octet="11",
            config_file="config/block.json",
        ),
        UnitTest(
            name="redirect",
            expected=xdp_action.XDP_TX,
            octet="22",
            config_file="config/redirect.json",
        ),
        UnitTest(
            name="bw_precedence",
            expected=xdp_action.XDP_DROP,
            config_file="config/bw_precedence.json",
            src_ip="10.10.66.66",
            scan=False,
        ),
        UnitTest(
            name="wb_precedence",
            expected=xdp_action.XDP_PASS,
            config_file="config/wb_precedence.json",
            src_ip="10.10.77.77",
            scan=False,
        ),
        UnitTest(
            name="ip_port_precedence",
            expected=xdp_action.XDP_DROP,
            config_file="config/ip_port_precedence.json",
            src_ip="10.10.88.88",
            scan=False,
            port=1337,
        ),
    ]

    print(f"running {Fore.BLUE + 'unit tests' + Fore.RESET}...")

    for test in tests:
        test.run(args.target)
