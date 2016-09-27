#!/usr/bin/env python
# -*- encoding: utf-8 -*-

"""
This script aim is to try to solve some well known ciphers
Author: BlackyFox
https://github.com/BlackyFox
"""

import os
import argparse
import sys
import string
import logging
import git
import csv
import signal
import colorama
import subprocess
import ctypes


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-v', '--verbose', help="increase output verbosity", action="store_true")
    args = parser.parse_args(arguments)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.debug("Debug mode activated")

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
