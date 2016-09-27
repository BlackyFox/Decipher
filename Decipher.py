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


def caesarDecrypt(cipher):
    logging.debug("Caesar decrypt")
    while True:
        know_key = raw_input("Do you know the Caesar cipher key (y or n)? ")
        if know_key.lower() == "y":
            logging.debug("Known key")
            while True:
                key = int(raw_input("Please, enter the key number (between 1 and 26): "))
                if (key >= 1 and key <= 26):
                    break
                else:
                    print(str(key) + " is not a valid key number.")
            translated = ""
            for symbol in cipher:
                if symbol.isalpha():
                    num = ord(symbol)
                    num += key

                    if symbol.isupper():
                        if num > ord('Z'):
                            num -= 26
                        elif num < ord('A'):
                            num += 26
                    elif symbol.islower():
                        if num > ord('z'):
                            num -= 26
                        elif num < ord('a'):
                            num += 26
                    translated += chr(num)
                else:
                    translated += symbol
            print(translated)
            break
        if know_key.lower() == "n":
            logging.debug("Unknown key")
            break
        else:
            print("We could not understant your answer...")

def vigenereDecrypt(cipher):
    logging.debug("Vigenère decrypt")

def monoalphabeticDecrypt(cipher):
    logging.debug("Monoalphabetic decrypt")

def adfgvxDecrypt(cipher):
    logging.debug("ADFGVX decrypt")

def playfairDecrypt(cipher):
    logging.debug("PlayFair decrypt")

def enigmaDecrypt(cipher):
    logging.debug("Enigma decrypt")


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    algos = parser.add_mutually_exclusive_group()
    algos.add_argument('-C', '--caesar', action='store_true', help="Caesar cipher")
    algos.add_argument('-V', '--vigenere', action='store_true', help="Vigenère cipher")
    algos.add_argument('-M', '--monoalphabetic', action='store_true', help="Monoalphabetic cipher")
    algos.add_argument('-A', '--adfgvx', action='store_true', help="ADFGVX cipher")
    algos.add_argument('-P', '--playfair', action='store_true', help="PlayFair cipher")
    algos.add_argument('-E', '--enigma', action='store_true', help="Enigma cipher")
    parser.add_argument('infile', type=argparse.FileType('r'), help="file containing the cipher")
    parser.add_argument('-v', '--verbose', help="increase output verbosity", action="store_true")
    args = parser.parse_args(arguments)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.debug("Debug mode activated")

    logging.debug(args.infile)

    cipher = ""
    for l in args.infile:
        cipher += l

    logging.debug(cipher)

    if args.caesar:
        caesarDecrypt(cipher)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
