#!./.venv/bin/python3

import argparse
from resource import setrlimit, RLIMIT_NOFILE
from random import randint
from multiprocessing import Process

from args import init_args
import packets

TARGET_CONFIG_PATH = "~/sheriff-buzz/config.json"
LOG_PATH = "/var/log/sheriff-buzz.log"


class ScalabilityTest:
    def __init__(self, name, num_ips, port_threshold):
        self.name = name
        self.num_ips = num_ips
        self.port_threshold = port_threshold

    def gen_port_list(self, num_packets):
        ports = []
        for i in range(num_packets):
            ports.append(packets.rand_port())
        return ports

    def gen_ip_list(self):
        ips = []
        for i in range(self.num_ips):
            ips.append(packets.rand_ip())
        return ips

    def run(self, target):
        processes = []

        # check we can send packets (requires raw socket access)
        packets.gen_packets(packets.rand_ip(), target, packets.SYN,
                            packets.rand_port())

        for i in range(self.num_ips):
            ports = self.gen_port_list(randint(self.port_threshold//2,
                                               self.port_threshold*2))
            p = Process(target=packets.gen_packets, args=(packets.rand_ip(),
                                                          target,
                                                          packets.SYN,
                                                          ports))

            p.start()
            processes.append(p)

            if i % 250 == 0:
                for p in processes:
                    p.join()
                    p.close()
                    processes.remove(p)

            '''
            packets.gen_packets(packets.rand_ip(), target, packets.SYN,
                                ports)
            '''

        for p in processes:
            p.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    init_args(parser)

    parser.add_argument("-n", "--num-ips", nargs="?", metavar="<num>",
                        required=True, type=int,
                        help="number of IPs to send packets from")

    args = parser.parse_args()

    test = ScalabilityTest(name="scalability", num_ips=args.num_ips,
                           port_threshold=(16*1024))

    setrlimit(RLIMIT_NOFILE, (65536*64*10, 65536*64*10))

    test.run(args.target)
