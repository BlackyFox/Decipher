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


def getMode():
    while True:
        print("So you wish to encrypt or decrypt a message?")
        mode = raw_input().lower()
        if mode in 'encrypt e'.split():
            return 'e'
        elif mode in 'decrypt d'.split():
            return 'd'
        else:
            print("Please, enter either \"encrypt\" or \"e\" to encrypt and \"decrypt\" or \"d\" to decrypt.")

def getCaesarKey():
    maxKey = 26
    key = 0
    while True:
        print("Please enter the key number (1-%s): " % (maxKey))
        key = int(raw_input())
        if (key >= 1 and key <= maxKey):
            return key
        else:
            print(str(key) + " is not a correct key.")

def caesarDecrypt(cipher):
    logging.debug("Caesar decrypt")
    while True:
        know_key = raw_input("Do you know the Caesar cipher key (y or n)? ")
        if know_key.lower() == "y":
            logging.debug("Known key")
            key = getCaesarKey()
            result = caesarCore('d', cipher, key)
            return result
        if know_key.lower() == "n":
            logging.debug("Unknown key")
            result = ''
            for key in range(0,27):
                result += str(key) + ": " + caesarCore('d', cipher, key)
                if result[-1:] != "\n":
                    result += "\n"
            return result
        else:
            print("We could not understant your answer...")

def caesarCore(mode, text, key):
    result = ''
    for l in text:
        if l.isalpha():
            num = ord(l)
            if mode is 'd':
                num -= key
            elif mode is 'e':
                num += key
            if l.isupper():
                if num > ord('Z'):
                    num -= 26
                elif num < ord('A'):
                    num += 26
            elif l.islower():
                if num > ord('z'):
                    num -= 26
                elif num < ord('a'):
                    num += 26
            result += chr(num)
        else:
            result += l
    return result

def caesarEncrypt(plain):
    logging.debug("Caesar encrypt")
    key = getCaesarKey()
    result = caesarCore('e', plain, key)
    return result


def vigenereDecrypt(cipher):
    logging.debug("Vigenère decrypt")

def monoalphabeticDecrypt(cipher):
    logging.debug("Monoalphabetic decrypt")

def adfgvxEncrypt(clear):
    logging.debug("ADFGVX encrypt")

def adfgvxDecrypt(cipher):
    logging.debug("ADFGVX decrypt")

def playfairDecrypt(cipher):
    logging.debug("PlayFair decrypt")

def enigmaDecrypt(cipher):
    logging.debug("Enigma decrypt")

def outputIt(text, output):
    if output:
        with open(output, 'w') as out:
            out.write("%s" % text)
    else:
        print(text)

def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-o', '--output', help="select output file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('-e', '--encrypt', action='store_true', help="choose the encrypt mode")
    mode.add_argument('-d', '--decrypt', action='store_true', help="choose the decrypt mode")
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

    if args.encrypt:
        logging.debug("Encrypt mode selected")
        mode = 'e'
    elif args.decrypt:
        logging.debug("Decrypt mode selected")
        mode = 'd'
    else:
        mode = getMode()

    if mode is 'e':
        logging.debug("Start encryption")
        if args.caesar:
            enc = caesarEncrypt(cipher)
            outputIt(enc, args.output)
    elif mode is 'd':
        logging.debug("Start decryption")
        if args.caesar:
            dec = caesarDecrypt(cipher)
            outputIt(dec, args.output)
    else:
        print("Error choosing mode.\nQuitting...")
        exit(1)



if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
