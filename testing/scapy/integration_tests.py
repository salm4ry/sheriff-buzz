#!./.venv/bin/python3

import argparse
from tqdm import tqdm
from colorama import Fore
from file_read_backwards import FileReadBackwards

import packets
import config
from args import init_args

TARGET_CONFIG_PATH = '~/sheriff-buzz/config.json'
LOG_PATH = '/var/log/sheriff-buzz.log'
NUM_TRIES = 5  # number of file reading attempts


def compare_packets(result, expected):
    '''Compare (ip, port) tuples'''
    return list(map(str, result)) == list(map(str, expected))


def read_log():
    log_line = ''

    # read file backwards to find correct test line
    with FileReadBackwards(LOG_PATH, encoding='utf-8') as f:
        for line in f:
            if 'test packet' in line:
                # strip leading and trailing whitepsace
                log_line = [x.strip() for x in line.split(',')]

                # parse log line
                log_packet = (log_line[-1].split(':'))
                return log_packet

    return None


class IntegrationTest:
    def __init__(self, name, num_tests, config_file):
        self.name = name
        self.num_tests = num_tests
        self.config_file = config_file

    def run(self, target, user):
        config.copy(src_path=self.config_file, dst_path=TARGET_CONFIG_PATH,
                    username=user)

        passed = failed = 0

        for i in tqdm(range(self.num_tests)):
            src_ip = packets.rand_src_ip()

            # send packet to random port
            dst_port = packets.rand_port()
            packets.gen_packets(src_ip, target, packets.SYN,
                                dst_port)

            # read log and compare output to expected
            result = read_log()

            if compare_packets(result, (src_ip, dst_port)):
                passed += 1
            else:
                failed += 1

        print(f"{Fore.BLUE + self.name}: "
              f"{Fore.YELLOW + str(self.num_tests) + Fore.RESET} total, "
              f"{Fore.GREEN + str(passed) + Fore.RESET} passed, "
              f"{Fore.RED + str(failed) + Fore.RESET} failed")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    init_args(parser)
    parser.add_argument('-n', '--num-tests', nargs='?', metavar='<num>',
                        default=100, help='number of tests to run')
    args = parser.parse_args()

    # set up test
    integration_test = IntegrationTest(name='integration_test',
                                       num_tests=args.num_tests,
                                       config_file='config/block.json')

    print(f"running {Fore.BLUE + 'integration tests' + Fore.RESET}...")

    # TODO run tests
    integration_test.run(args.target, args.user)
