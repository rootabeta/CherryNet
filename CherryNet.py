#!/usr/bin/python3
import argparse
import filecrypto
from libnmap.parser import NmapParser #NMAP
from lxml import etree as ET #XML

parser = argparse.ArgumentParser(
        prog = "CherryNet",
        description = "A utility to import nmap files into CherryTree for pentesters",
        epilog = "This utility only accepts XML-formatted CherryTree files. If you are using .ctz (encrypted XML) format, you must supply the decryption password."
)

parser.add_argument('cherrytreefile',help="path to the cherrytree file")
parser.add_argument('nmapxml',help="path to the xml file to use")

parser.add_argument('-p','--password',help="password to use for ctz files")
parser.add_argument('-n','--new-file',help="create a new file (default - merge into existing)",action='store_true')

args = parser.parse_args()


