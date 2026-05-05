"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSBridge

class BridgeTopo(Topo):
    "Create a bridge-like customized network topology according to Figure 1 in the lab0 description."

    def __init__(self):

        Topo.__init__(self)

        # TODO: add nodes and links to construct the topology; remember to specify the link properties
        
        # adding hosts
        h1 = self.addHost("h1", ip = "10.0.0.1")
        h2 = self.addHost("h2", ip = "10.0.0.2")
        h3 = self.addHost("h3", ip = "10.0.0.3")
        h4 = self.addHost("h4", ip = "10.0.0.4")

        # adding switches
        s1 = self.addSwitch("s1", cls=OVSBridge)
        s2 = self.addSwitch("s2", cls=OVSBridge)

        # adding links
        self.addLink(h1, s1, bw = 15, delay = "10ms", cls = TCLink) # e1
        self.addLink(h2, s1, bw = 15, delay = "10ms", cls = TCLink) # e2
        self.addLink(h3, s2, bw = 15, delay = "10ms", cls = TCLink) # e3
        self.addLink(h4, s2, bw = 15, delay = "10ms", cls = TCLink) # e4
        self.addLink(s1, s2, bw = 20, delay = "45ms", cls = TCLink) # e5

topos = {'bridge': (lambda: BridgeTopo())}

# Automisation via script possible with
# net = Mininet(BridgeTopo) # Create a network with the topology topo
# net.start() # Start the network
# net.pingAll() # Perform ping tests
# net.stop() 

# TCP
#  
# h1 listening
#   > h1$ iperf -s
#   > h3$ iperf -c 10.0.0.1 -t 20
# 
# RESULT on h1:
# ------------------------------------------------------------
# Server listening on TCP port 5001
# TCP window size: 85.3 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.1 port 5001 connected with 10.0.0.3 port 57204
# [ ID] Interval            Transfer     Bandwidth
# [  1] 0.0000-26.3981 sec  39.4 MBytes  12.5 Mbits/sec
# => Throughput = (39.4 * 8) Mbits / 26.3981 sec = 11.9403 Mbits/sec
# 
# RESULT on h3:
# ------------------------------------------------------------
# Client connecting to 10.0.0.1, TCP port 5001
# TCP window size: 85.3 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.3 port 57204 connected with 10.0.0.1 port 5001
# [ ID] Interval            Transfer     Bandwidth
# [  1] 0.0000-26.5445 sec  39.4 MBytes  12.4 Mbits/sec
# => Throughput = (39.4 * 8) Mbits / 26.5445 sec = 11.8744 Mbits/sec
# 
# ...
# 
# h3 listening
#   > h3$ iperf -s
#   > h1$ iperf -c 10.0.0.3 -t 20
# 
# RESULT on h1:
# ------------------------------------------------------------
# Client connecting to 10.0.0.3, TCP port 5001
# TCP window size: 85.3 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.1 port 37876 connected with 10.0.0.3 port 5001
# [ ID] Interval            Transfer     Bandwidth
# [  1] 0.0000-28.1003 sec  43.1 MBytes  12.9 Mbits/sec
# => Throughput = (43.1 * 8) Mbits / 28.1003 sec = 12.2703 Mbits/sec
# 
# RESULT on h3:
# ------------------------------------------------------------
# Server listening on TCP port 5001
# TCP window size: 85.3 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.3 port 5001 connected with 10.0.0.1 port 37876
# [ ID] Interval            Transfer     Bandwidth
# [  1] 0.0000-27.9543 sec  43.1 MBytes  12.9 Mbits/sec
# => Throughput = (43.1 * 8) Mbits / 27.9543 sec = 12.2244 Mbits/sec
#
# =======================================================================================
#
# UDP
# 
# h1 listening
#   > h1$ iperf -s -u
#   > h3$ iperf -c ip.to.server -t 20 -u
# 
# RESULT on h1:
# ------------------------------------------------------------
# Server listening on UDP port 5001
# UDP buffer size:  208 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.1 port 5001 connected with 10.0.0.3 port 41597
# [ ID] Interval            Transfer     Bandwidth        Jitter    Lost/Total Datagrams
# [  1] 0.0000-20.0103 sec  2.51 MBytes  1.05 Mbits/sec   1.294 ms  0/1787 (0%)
# [  5] WARNING: ack of last datagram failed.
# [  2] local 10.0.0.1 port 5001 connected with 10.0.0.3 port 41597
# [ ID] Interval            Transfer     Bandwidth        Jitter    Lost/Total Datagrams
# [  2] 0.0000-0.0110 sec   2.87 KBytes  2.13 Mbits/sec   0.690 ms  1796/1798 (1e+02%)
# [  6] WARNING: ack of last datagram failed.
# => Throughput ???
#
# RESULT on h3:
# ------------------------------------------------------------
# Client connecting to 10.0.0.1, UDP port 5001
# Sending 1470 byte datagrams, IPG target: 11215.21 us (kalman adjust)
# UDP buffer size:  208 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.3 port 41597 connected with 10.0.0.1 port 5001
# [ ID] Interval            Transfer     Bandwidth
# [  1] 0.0000-20.0194 sec  2.51 MBytes  1.05 Mbits/sec
# [  1] Sent 1788 datagrams
# [  1] Server Report:
# [ ID] Interval            Transfer     Bandwidth        Jitter    Lost/Total Datagrams
# [  1] 0.0000-20.0103 sec  2.51 MBytes  1.05 Mbits/sec   1.293 ms  0/1787 (0%)
# => Throughput ???
#
# ...
# 
# h3 listening
#   > h3$ iperf -s -u
#   > h1$ iperf -c ip.to.server -t 20 -u
# RESULT on h1:
# ------------------------------------------------------------
# Client connecting to 10.0.0.3, UDP port 5001
# Sending 1470 byte datagrams, IPG target: 11215.21 us (kalman adjust)
# UDP buffer size:  208 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.1 port 46301 connected with 10.0.0.3 port 5001
# [ ID] Interval            Transfer     Bandwidth
# [  1] 0.0000-20.0211 sec  2.51 MBytes  1.05 Mbits/sec
# [  1] Sent 1788 datagrams
# [  1] Server Report:
# [ ID] Interval            Transfer     Bandwidth        Jitter    Lost/Total Datagrams
# [  1] 0.0000-20.0168 sec  2.51 MBytes  1.05 Mbits/sec   1.052 ms  0/1787 (0%)
# => Throughput ???
# 
# RESULT on h3:
# ------------------------------------------------------------
# Server listening on UDP port 5001
# UDP buffer size:  208 KByte (default)
# ------------------------------------------------------------
# [  1] local 10.0.0.3 port 5001 connected with 10.0.0.1 port 46301
# [ ID] Interval            Transfer     Bandwidth        Jitter    Lost/Total Datagrams
# [  1] 0.0000-20.0168 sec  2.51 MBytes  1.05 Mbits/sec   1.052 ms  0/1787 (0%)
# [  5] WARNING: ack of last datagram failed.
# [  2] local 10.0.0.3 port 5001 connected with 10.0.0.1 port 46301
# [ ID] Interval            Transfer     Bandwidth        Jitter     Lost/Total Datagrams
# [  2] 0.0000-0.0109 sec   2.87 KBytes  2.16 Mbits/sec   0.682 ms   1796/1798 (1e+02%)
# [  6] WARNING: ack of last datagram failed.
# => Throughput ???

# Pinging
# 
# RESULT for h1 -> h3 (ping 10.0.0.3 -c 20)
# ==========================================================
# PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
# 64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=149 ms
# 64 bytes from 10.0.0.3: icmp_seq=2 ttl=64 time=180 ms
# 64 bytes from 10.0.0.3: icmp_seq=3 ttl=64 time=178 ms
# 64 bytes from 10.0.0.3: icmp_seq=4 ttl=64 time=133 ms
# 64 bytes from 10.0.0.3: icmp_seq=5 ttl=64 time=155 ms
# 64 bytes from 10.0.0.3: icmp_seq=6 ttl=64 time=144 ms
# 64 bytes from 10.0.0.3: icmp_seq=7 ttl=64 time=144 ms
# 64 bytes from 10.0.0.3: icmp_seq=8 ttl=64 time=173 ms
# 64 bytes from 10.0.0.3: icmp_seq=9 ttl=64 time=143 ms
# 64 bytes from 10.0.0.3: icmp_seq=10 ttl=64 time=159 ms
# 64 bytes from 10.0.0.3: icmp_seq=11 ttl=64 time=135 ms
# 64 bytes from 10.0.0.3: icmp_seq=12 ttl=64 time=144 ms
# 64 bytes from 10.0.0.3: icmp_seq=13 ttl=64 time=172 ms
# 64 bytes from 10.0.0.3: icmp_seq=14 ttl=64 time=156 ms
# 64 bytes from 10.0.0.3: icmp_seq=15 ttl=64 time=155 ms
# 64 bytes from 10.0.0.3: icmp_seq=16 ttl=64 time=140 ms
# 64 bytes from 10.0.0.3: icmp_seq=17 ttl=64 time=146 ms
# 64 bytes from 10.0.0.3: icmp_seq=18 ttl=64 time=146 ms
# 64 bytes from 10.0.0.3: icmp_seq=19 ttl=64 time=155 ms
# 64 bytes from 10.0.0.3: icmp_seq=20 ttl=64 time=153 ms
#
# --- 10.0.0.3 ping statistics ---
# 20 packets transmitted, 20 received, 0% packet loss, time 19829ms
# rtt min/avg/max/mdev = 133.379/153.010/180.000/13.203 ms
#
# RESULT for h3 -> h1 (ping 10.0.0.1 -c 20)
# PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
# 64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=0.026 ms
# 64 bytes from 10.0.0.3: icmp_seq=2 ttl=64 time=0.038 ms
# 64 bytes from 10.0.0.3: icmp_seq=3 ttl=64 time=0.039 ms
# 64 bytes from 10.0.0.3: icmp_seq=4 ttl=64 time=0.045 ms
# 64 bytes from 10.0.0.3: icmp_seq=5 ttl=64 time=0.045 ms
# 64 bytes from 10.0.0.3: icmp_seq=6 ttl=64 time=0.044 ms
# 64 bytes from 10.0.0.3: icmp_seq=7 ttl=64 time=0.038 ms
# 64 bytes from 10.0.0.3: icmp_seq=8 ttl=64 time=0.043 ms
# 64 bytes from 10.0.0.3: icmp_seq=9 ttl=64 time=0.043 ms
# 64 bytes from 10.0.0.3: icmp_seq=10 ttl=64 time=0.046 ms
# 64 bytes from 10.0.0.3: icmp_seq=11 ttl=64 time=0.048 ms
# 64 bytes from 10.0.0.3: icmp_seq=12 ttl=64 time=0.039 ms
# 64 bytes from 10.0.0.3: icmp_seq=13 ttl=64 time=0.044 ms
# 64 bytes from 10.0.0.3: icmp_seq=14 ttl=64 time=0.052 ms
# 64 bytes from 10.0.0.3: icmp_seq=15 ttl=64 time=0.038 ms
# 64 bytes from 10.0.0.3: icmp_seq=16 ttl=64 time=0.037 ms
# 64 bytes from 10.0.0.3: icmp_seq=17 ttl=64 time=0.044 ms
# 64 bytes from 10.0.0.3: icmp_seq=18 ttl=64 time=0.057 ms
# 64 bytes from 10.0.0.3: icmp_seq=19 ttl=64 time=0.039 ms
# 64 bytes from 10.0.0.3: icmp_seq=20 ttl=64 time=0.040 ms

# --- 10.0.0.3 ping statistics ---
# 20 packets transmitted, 20 received, 0% packet loss, time 21231ms
# rtt min/avg/max/mdev = 0.026/0.042/0.057/0.006 ms