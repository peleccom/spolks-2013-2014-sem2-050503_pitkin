#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import socket
import signal
import struct
import time
import errno

TTL_DEFAULT = 52

MAXWAIT = 10#	/* max time to wait for response, sec. */
MAXPACKET = 4096#	/* max packet size */

ICMP_ECHO_REQUEST = 8
ICMP_ECHOREPLY = 0

ICMP_TYPES = [
    "Echo Reply",
    "ICMP 1",
    "ICMP 2",
    "Destination Host unreachable",
    "Source Quench",
    "Redirect",
    "ICMP 6",
    "ICMP 7",
    "Echo",
    "ICMP 9",
    "ICMP 10",
    "Time Exceeded",
    "Parameter Problem",
    "Timestamp",
    "Timestamp Reply",
    "Info Request",
    "Info Reply",
]


def checksum(s):
    csum = 0
    countTo = (len(s) / 2) * 2

    count = 0
    while count < countTo:
        thisVal = ord(s[count + 1]) * 256 + ord(s[count])

        csum = csum + thisVal

        csum = csum & 0xffffffffL

        count = count + 2

    if countTo < len(s):
        csum = csum + ord(s[len(s) - 1])
        csum = csum & 0xffffffffL

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum

    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


class IP_HEADER(object):
    def __init__(self):
        pass

    def unpack(self, header):
        pass

    def pack(self):
        pass


class ICMP_HEADER(object):
    def __init__(self):
        self.type = None
        self.code = None
        self.icmp_id = None
        self.icmp_seq = None
        self.data = None
        self.checksum = None

    def unpack(self, packet):
        header = packet[20:28]
        self.type, self.code, self.checksum, self.icmp_id, self.icmp_seq = struct.unpack('bbHHh', header)
        self.data = packet[28:]

    def calc_checksum(self):
        s = struct.pack("bbHHh", self.type, self.code, 0, self.icmp_id, self.icmp_seq)
        s += self.data
        self.checksum = checksum(s)

    def pack(self):
        if self.checksum == None:
            self.calc_checksum()
        header = struct.pack("bbHHh", self.type, self.code, socket.htons(self.checksum), self.icmp_id, self.icmp_seq)
        return header + self.data


class SimplePing(object):
    def __init__(self, destination):
        self.datalen = 64 - 8
        self.icmp = socket.getprotobyname("icmp")
        self.my_id = os.getpid() & 0xFFFF
        self.ntransmitted = 0 #seq number
        self.hostname = None
        self.npackets = 0
        self.nreceived = 0
        self.tmin = 99999999999999999
        self.tmax = 0
        self.tsum = 0
        self.finish_callback = None
        print_packet_callback = None

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.icmp)
            self.s.settimeout(2)
        except socket.error, e:
            print "You are root user? Are you sure?"
            sys.exit(1)
        try:
            ip = socket.inet_aton(destination)
            #ip passed
            self.destination = destination
            self.hostname = destination
        except:
            try:
                #hostname passed
                self.destination = socket.gethostbyname(destination)
                self.hostname = destination
            except socket.gaierror, e:
                print "ping: unknown host %s" % destination
                sys.exit(1)

    def pinger(self):
        """send ping request"""
        icmp_header = ICMP_HEADER()
        icmp_header.type = ICMP_ECHO_REQUEST
        icmp_header.code = 0
        icmp_header.icmp_id = self.my_id
        icmp_header.icmp_seq = self.ntransmitted
        self.ntransmitted += 1
        bytes_in_double = struct.calcsize("d")
        padding_bytes = self.datalen - bytes_in_double
        cur_time = time.time()
        data = struct.pack("d", cur_time) + padding_bytes * "x"
        icmp_header.data = data
        icmp_data = icmp_header.pack()
        self.s.sendto(icmp_data, (self.destination, 0))

    def recv(self):
        packet, address = self.s.recvfrom(1024)
        icmp_header = ICMP_HEADER()
        cur_time = time.time()
        icmp_header.unpack(packet)
        if (icmp_header.type == ICMP_ECHOREPLY) and (icmp_header.icmp_id == self.my_id) :
            bytes_in_double = struct.calcsize("d")
            ptime = icmp_header.data[:bytes_in_double]
            ptime = struct.unpack("d", ptime)[0]
            triptime = (cur_time - ptime) * 1000

            if self.print_packet_callback:
                self.print_packet_callback(self, icmp_header, triptime)

            self.tsum += triptime;
            if triptime < self.tmin:
                self.tmin = triptime;
            if triptime > self.tmax:
                self.tmax = triptime;
            self.nreceived += 1
        else:
            print "From %s icmp_seq=%s %s" % (address[0], icmp_header.icmp_seq, ICMP_TYPES[icmp_header.type])

    def catcher(self):
        self.pinger()
        if (self.npackets == 0) or (self.ntransmitted < self.npackets):
            signal.alarm(1)
        else:
            if (self.nreceived):
                self.waittime = 2. * self.tmax / 1000
                if self.waittime == 0:
                    self.waittime = 1
                else:
                    self.waittime = MAXWAIT
                signal.signal(signal.SIGALRM, self.finish)
                print "%s bytes from %s: icmp_req=%s time=%s ms" % (64, ping.hostname, )
                signal.alarm(self.waittime)

    def run(self):
        self.pinger()
        self.catcher()
        while True:
            try:
                packet = self.recv()
            except socket.error as e:
                if e.errno == errno.EINTR:
                    continue
            if (self.npackets and self.nreceived >= self.npackets):
                if self.finish_callback:
                    self.finish_callback(self)

    def catcher_handler(self, signal_num, frame):
        if (self.npackets == 0) or (self.ntransmitted < self.npackets):
            signal.alarm(1)
        self.pinger()

    def set_finish_callback(self, callback):
        self.finish_callback = callback

    def set_print_packet_callback(self, callback):
        self.print_packet_callback = callback

    def finish_handler(self, signum, frame):
        self.s.close()
        if self.finish_callback:
            self.finish_callback(self)


def print_pack(ping, icmp_header, rtt):
    if icmp_header.type == ICMP_ECHOREPLY:
        print "%s bytes from %s: icmp_req=%s time=%1.1f ms" % (64, ping.hostname, icmp_header.icmp_seq, rtt)
    else:
        print "%s bytes from %s: %s" % (64, ping.hostname, icmp_header.type)


def finish(ping):
    """print ping statistic"""
    print("\n")
    print "\n----%s PING Statistics----\n" % ping.hostname,
    print "%d packets transmitted, " % ping.ntransmitted,
    print "%d packets received, " % ping.nreceived,
    if (ping.ntransmitted):
        if ( ping.nreceived > ping.ntransmitted):
            print "-- somebody's printing up packets!",
        else:
            print "%d%% packet loss" % (((ping.ntransmitted - ping.nreceived) * 100) /
                                        ping.ntransmitted),
    print("\n")
    if ping.nreceived:
        print("round-trip (ms)  min/avg/max = %d/%d/%d\n" % (ping.tmin,
                                                             ping.tsum / ping.nreceived,
                                                             ping.tmax ))
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='Python implementation of the ICMP  ping command')
    parser.add_argument("destination", help="ip address or domain name")
    args = parser.parse_args()
    #not best method, to check for root privilegies
    if os.geteuid() != 0:
        print "You are not superuser. Please run program as root!!!"
        sys.exit(2)

    ping = SimplePing(args.destination)
    ping.set_finish_callback(finish)
    ping.set_print_packet_callback(print_pack)
    print("PING %s(%s) : %d data bytes\n" % (ping.hostname, ping.destination, ping.datalen))
    signal.signal(signal.SIGINT, ping.finish_handler)
    signal.signal(signal.SIGALRM, ping.catcher_handler)
    ping.run()


if __name__ == "__main__":
    main()
