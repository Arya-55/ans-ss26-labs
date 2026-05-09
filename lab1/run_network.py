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

#!/bin/env python3
from collections import defaultdict
from pprint import pprint

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController, Switch
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel
import requests
from ryu.topology import switches


class NetworkTopo(Topo):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.addHost("ext", ip="192.168.1.123/24")
        self.addHost("h1", ip="10.0.1.2/24")
        self.addHost("h2", ip="10.0.1.3/24")
        self.addHost("ser", ip="10.0.2.2/24")

        self.addSwitch("s1", dpid=f"{1:016d}")
        self.addSwitch("s2", dpid=f"{2:016d}")
        self.addSwitch("s3", dpid=f"{3:016d}")

        self.addLink("h1", "s1", bw=15, delay="10ms")
        self.addLink("h2", "s1", bw=15, delay="10ms")
        self.addLink("s1", "s3", bw=15, delay="10ms")
        self.addLink("s3", "ext", bw=15, delay="10ms")
        self.addLink("s3", "s2", bw=15, delay="10ms")
        self.addLink("s2", "ser", bw=15, delay="10ms")


class SwitchFlowTester:

    def __init__(self, net: Mininet):
        self.net = net

        self.test_data_switch_flows = defaultdict(dict)
        switchname = "s1"
        port_to_hop = self.get_port_to_hop(switchname)
        self.test_data_switch_flows[switchname][net.get("h1").MAC()] = port_to_hop["h1"]
        self.test_data_switch_flows[switchname][net.get("h2").MAC()] = port_to_hop["h2"]
        self.test_data_switch_flows[switchname][net.get("ext").MAC()] = port_to_hop["s3"]
        self.test_data_switch_flows[switchname][net.get("ser").MAC()] = port_to_hop["s3"]

        switchname = "s2"
        port_to_hop = self.get_port_to_hop(switchname)
        self.test_data_switch_flows[switchname][net.get("h1").MAC()] = port_to_hop["s3"]
        self.test_data_switch_flows[switchname][net.get("h2").MAC()] = port_to_hop["s3"]
        self.test_data_switch_flows[switchname][net.get("ext").MAC()] = port_to_hop["s3"]
        self.test_data_switch_flows[switchname][net.get("ser").MAC()] = port_to_hop["ser"]

        switchname = "s3"
        port_to_hop = self.get_port_to_hop(switchname)
        self.test_data_switch_flows[switchname][net.get("h1").MAC()] = port_to_hop["s1"]
        self.test_data_switch_flows[switchname][net.get("h2").MAC()] = port_to_hop["s1"]
        self.test_data_switch_flows[switchname][net.get("ext").MAC()] = port_to_hop["ext"]
        self.test_data_switch_flows[switchname][net.get("ser").MAC()] = port_to_hop["s2"]

        for switchname in self.test_data_switch_flows:
            for hostmac in self.test_data_switch_flows[switchname]:
                print(f"Switch={switchname}: {hostmac} --> {self.test_data_switch_flows[switchname][hostmac]}")

    def get_port_to_hop(self, switchname):
        switch = self.net.get(switchname)
        ret = {}
        for port_no, intf in switch.intfs.items():
            if port_no == 0:  # except lo
                continue
            link = intf.link
            if link.intf1.node.name != switchname:
                ret[link.intf1.node.name] = port_no
            else:
                ret[link.intf2.node.name] = port_no
        return ret

    @staticmethod
    def cast_to_int_if_possible(arg):
        try:
            return int(arg)
        except ValueError:
            return arg

    def parse_action_str(self, action_str: str):
        action, target = action_str.split(":")
        return action, self.cast_to_int_if_possible(target)

    def test(self):
        flows = defaultdict(dict)
        for switch in self.net.switches:
            sdpid = int(switch.dpid)
            resp = requests.get(f"http://localhost:8080/stats/flow/{sdpid}")
            flows_json = resp.json()[str(sdpid)]

            for d in flows_json:
                match = d["match"].get("dl_dst")
                flows[switch.name][match] = [d["actions"]]
                for actions in flows[switch.name][match]:
                    for action_str in actions:
                        _, port = self.parse_action_str(action_str)
                        flows[switch.name][match] = port

        for switchname in self.test_data_switch_flows:
            for hostmac, port_no in self.test_data_switch_flows[switchname].items():
                test = flows[switchname].get(hostmac) == port_no
                if test:
                    print(f"Success: Switch={switchname}: Rule: {hostmac} --> {port_no} == {flows[switchname].get(hostmac)}")
                else:
                    print(f"Failure: Switch={switchname}: Rule: {hostmac} --> {port_no} != {flows[switchname].get(hostmac)}")


def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1', 
        controller=RemoteController, 
        ip="127.0.0.1", 
        port=6653)
    net.start()
    net.pingAllFull()
    switch_flow_tester = SwitchFlowTester(net)
    switch_flow_tester.test()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()