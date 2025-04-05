#!./.venv/bin/python3

import argparse
from colorama import Fore, Style

import packets
import config
from results import lookup, print_xdp_result, xdp_action
from args import init_args

TARGET_CONFIG_PATH = '~/sheriff-buzz/config.json'
TEST_PORT = 12345
TEST_MAP_NAME = 'test_results'


class UnitTest:
    def __init__(self, name, expected, config_file,
                 src_ip='', octet='', scan=True,
                 port_threshold=100):
        self.name = name                      # test name (used in output)
        self.expected = expected              # expected return value
        self.config_file = config_file        # path to config file
        self.do_scan = scan                   # do a port scan?
        self.port_threshold = port_threshold  # sheriff-buzz port threshold

        # source IP (leave empty for random)
        if not src_ip:
            self.src_ip = packets.rand_src_ip(octet)
        else:
            self.src_ip = src_ip

    def port_scan(self, target, port_threshold):
        '''Perform a port scan (+1 packet'''
        # scan first 100 ports
        packets.gen_packets(self.src_ip, target, packets.SYN,
                            (1, port_threshold), verbose=True)
        # send another packet in order to observe XDP return value
        packets.gen_packets(self.src_ip, target, packets.SYN,
                            [TEST_PORT], verbose=True)

    def single_packet(self, target):
        '''Send a single packet'''
        packets.gen_packets(self.src_ip, target, packets.SYN,
                            [TEST_PORT])

    def run(self, target, user):
        config.copy(src_path=self.config_file, dst_path=TARGET_CONFIG_PATH,
                    username=user)

        if (self.do_scan):
            self.port_scan(target, self.port_threshold)
        else:
            self.single_packet(target)

        # check results
        res = lookup(TEST_MAP_NAME, self.src_ip)

        if res is not None:
            print_xdp_result(self.name, res, self.expected)
        else:
            print(f"{Fore.BLUE + self.name}:{Fore.RESET} {Fore.YELLOW}"
                  "failed to run")
            print(Style.RESET_ALL)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    init_args(parser)
    args = parser.parse_args()

    tests = [UnitTest(name='block', expected=xdp_action.XDP_DROP,
                      octet='11', config_file='config/block.json'),
             UnitTest(name='redirect', expected=xdp_action.XDP_TX,
                      octet='22', config_file='config/redirect.json'),
             UnitTest(name='bw_precedence', expected=xdp_action.XDP_DROP,
                      config_file='config/bw_precedence.json',
                      src_ip="10.10.66.66", scan=False),
             UnitTest(name='wb_precedence', expected=xdp_action.XDP_PASS,
                      config_file='config/wb_precedence.json',
                      src_ip="10.10.77.77", scan=False)]

    print(f"running {Fore.BLUE + 'unit tests' + Fore.RESET}...")

    for test in tests:
        test.run(args.target, args.user)
