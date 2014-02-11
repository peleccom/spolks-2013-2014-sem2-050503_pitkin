#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse

TTL_DEFAULT = 52


def main():
    parser = argparse.ArgumentParser(description='Python implementation of the ICMP  ping command')
    parser.add_argument("destination", help="ip address or domain name")
    parser.add_argument("--ttl", type=int, help='hops limit', default=TTL_DEFAULT)

    args = parser.parse_args()
    print args


if __name__ == "__main__":
    main()
