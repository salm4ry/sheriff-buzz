#!/usr/bin/env python3

import argparse


def init_args(parser: argparse.ArgumentParser):
    parser.add_argument(
        "-t", "--target", nargs="?", metavar="<IP>", required=True,
        help="target IP"
    )
