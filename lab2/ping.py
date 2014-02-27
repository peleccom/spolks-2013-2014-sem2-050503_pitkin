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
                thisVal = ord(s[count+1]) * 256 + ord(s[count])

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
    def __init__(self,
                 len = 20,
                 id = 0,
                 ttl = 0,
                 p = 0,
                 sum = 0,
                 src = None,
                 dst = None,
                 data = ''):
        self.v = 4
        self.hl = 5        # this implement punts on options
        self.tos = 0
        self.len = len      # begin with header length
        self.id = id
        self.df = 0
        self.off = 0
        self.ttl = ttl
        self.p = p
        self.sum = sum
        self.src = src
        self.dst = dst
        self.data = data
        self.raw_packet = ''
        
    def unpack(self, header):
        # The kernel computes the checksum, even on a raw packet.
        b1 = ord(packet[0])
        self.v = (b1 >> 4) & 0x0f
        self.hl = b1 & 0x0f
        if self.v != IPVERSION:
            raise ValueError, "cannot handle IPv%d packets" % self.v
        hl = self.hl * 4
  
        # verify the checksum
        self.sum = struct.unpack('!H', packet[10:12])[0] & 0xffff
        our_cksum = checksum(packet[:20])
        if our_cksum != 0:
            raise ValueError, packet
  
        # unpack the fields
        elts = struct.unpack('!ccHHHcc', packet[:hl-10])
        # struct didn't do !<> when this was written
        self.tos = ord(elts[1])
        self.len = elts[2] & 0xffff
        self.id = elts[3] & 0xffff
        self.off = elts[4] & 0xffff
        self.ttl = ord(elts[5])
        self.p = ord(elts[6])
        self.data = packet[hl:]
        self.src = packet[hl-8:hl-4]
        self.dst = packet[hl-4:hl]
        self.__unparse_addrs()

    def pack(self):
  
        self.len = self.hl * 4 + len(self.data)
        self._parse_addrs()
        # create the packet
        header =  struct.pack('!ccHHHcc',
                              chr((self.v & 0x0f) << 4
                                  | (self.hl & 0x0f)),    # 4bits each
                              chr(self.tos & 0xff),
                              self.len,
                              self.id,
                              (self.df & 0x01) << 14
                                   | self.off,
                              chr(self.ttl & 0xff),
                              chr(self.p & 0xff))
        self.sum =  checksum(header + '\000\000' + self.__src +
                                  self.__dst)
        packet = header + struct.pack('!H', self.sum) \
                     + self.__src + self.__dst
        packet = packet + self.data
  
        self.__packet = packet
        return self.__packet
    
    def _parse_addrs(self):
        try:
            self.__src = socket.inet_aton(self.src)
        except socket.error:
            try:
                self.__src = socket.inet_aton(socket.gethostbyname(self.src))
            except socket.gaierror:
                raise ValueError, "invalid source address"
        try:
            self.__dst = socket.inet_aton(self.dst)
        except socket.error:
            try:
                self.__dst = socket.inet_aton(socket.gethostbyname(self.dst))
            except socket.gaierror:
                raise ValueError, "invalid source address"


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
        self.type, self.code, self.checksum, self.icmp_id, self.icmp_seq = struct.unpack('bbHHh',header)
        self.data = packet[28:]

    def calc_checksum(self):
        s = struct.pack("bbHHh", self.type, self.code, 0, self.icmp_id, self.icmp_seq)
        s += self.data
        self.checksum = checksum(s)

    def pack(self):
        if self.checksum == None:
            self.calc_checksum()
        header = struct.pack("bbHHh", self.type, self.code,socket.htons(self.checksum),self.icmp_id, self.icmp_seq)
        return header + self.data




class SimplePing(object):
    def __init__(self, destination, ttl=TTL_DEFAULT, source=None): 
        self.datalen  = 64 - 8
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
        self.ttl = ttl
        if source:
            try:
                socket.inet_aton(source)
                self.source = source
            except socket.error:
                try:
		    ip = socket.gethostbyname(source)
                    socket.inet_aton(ip)
                    self.source = ip
                except socket.gaierror:
                    raise ValueError, "invalid source address"
        else:
            self.source = "0.0.0.0"#socket.gethostbyname(socket.gethostname())
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.icmp)
            #self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
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
        ip_header = IP_HEADER(len = 20 + len(icmp_data),
            ttl=self.ttl, src=self.source, dst=self.destination, 
            data=icmp_data,
            p= socket.IPPROTO_ICMP)
        ip_data = ip_header.pack()
        self.s.sendto(ip_data, (self.destination, 0))

    def recv(self):
        packet, address = self.s2.recvfrom(1024)
        icmp_header = ICMP_HEADER()
        cur_time = time.time()
        icmp_header.unpack(packet)
        if (icmp_header.type == ICMP_ECHOREPLY) and (icmp_header.icmp_id == self.my_id):
            bytes_in_double = struct.calcsize("d")
            ptime = icmp_header.data[:bytes_in_double]
            ptime = struct.unpack("d", ptime)[0]
            triptime = (cur_time - ptime) *1000
            
            if self.print_packet_callback:
                self.print_packet_callback(self, icmp_header,  triptime)
            
            self.tsum += triptime;
            if  triptime <  self.tmin:
                self.tmin = triptime;
            if  triptime >  self.tmax:
                self.tmax = triptime;
            self.nreceived += 1
        else:
	    l = packet[0x30:]
            l = l[4:6]
            packet_id = struct.unpack("H", l)[0]
            if (packet_id == self.my_id):
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
                packet  = self.recv()
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
        self.s2.close()
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
        if( ping.nreceived > ping.ntransmitted):
            print "-- somebody's printing up packets!",
        else:
            print "%d%% packet loss" % (((ping.ntransmitted-ping.nreceived)*100) /
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
    parser.add_argument("-t","--ttl", type=int, help='hops limit', default=TTL_DEFAULT)
    parser.add_argument("-s","--source", help="source address", default=None)
    args = parser.parse_args()
    #not best method, to check for root privilegies
    if os.geteuid() != 0:
        print "You are not superuser. Please run program as root!!!"
        sys.exit(2)

    ping = SimplePing(args.destination, ttl=args.ttl, source=args.source)
    ping.set_finish_callback(finish)
    ping.set_print_packet_callback(print_pack)
    print("PING %s(%s) : %d data bytes\n" % (ping.hostname, ping.destination, ping.datalen))
    signal.signal(signal.SIGINT, ping.finish_handler)
    signal.signal(signal.SIGALRM, ping.catcher_handler)
    ping.run()


if __name__ == "__main__":
    main()
