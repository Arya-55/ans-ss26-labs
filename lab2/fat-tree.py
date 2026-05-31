"""
 Copyright (c) 2025 Computer Networks Group @ UPB

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

#!/usr/bin/env python3

import os
import subprocess
import time
from typing import Dict

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

import networkx as nx
import matplotlib.pyplot as plt

import topo

# def _generate_net_graph(net):
#     graph = nx.DiGraph()


#     for h in net.hosts:
#         print(h) 
#         graph.add_node(h.name, type = "host", ip = h.IP)

#     for s in net.switches:
#         graph.add_node(s.name, type = "switch", ip = s.params.get("ip"))

#     for l in net.links:
#         lnode = l.intf1.node.name
#         rnode = l.intf2.node.name
#         graph.add_edge(lnode, rnode)

#     node_positions = nx.spring_layout(graph)


#     #positions = nx.get_node_attributes(graph, "pos")

#     nx.draw(graph, node_positions, with_labels=True)
#     # nx.draw_networkx_nodes(
#     #     graph, 
#     #     node_positions,
#     #     nodelist=graph.nodes,
#     #     node_shape='o',
#     #     node_size=300
#     # )
#     # nx.draw_networkx_edges(graph, node_positions, width=10)
#     # nx.draw_networkx_labels(graph, node_positions)

#     plt.title(f"Generated Fatnet Topology {len(graph.edges)}")
#     plt.axis("off")
#     plt.savefig("topology.png", dpi=300, bbox_inches="tight")


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)
        
        # Adding Switches, Switch naming convention:
        # The switch type identifier is between the two numbers because we would otherwise need another divider
        # core (c) switches: "s<j>c<i>" where j and i are their position in the grid (ip: 10.num_ports.j.i)
        # aggr (a) swichtes: "s<p>a<s>" where p is their pod-id and s is their own id (ip: 10.p.s.1)    => s in [num_ports/2, num_ports - 1]
        # edge (e) switches: "s<p>e<s>" where p is their pod-id and s is their own id (ip: 10.p.s.1)    => s in [0, num_ports/2 - 1]
        switches = ft_topo.switches
        for switch in switches:
            # ip addresses need to be assigned at runtime, hence the dict in this class
            match switch.type:
                case "core":
                    name = f"s{switch.switch}c{switch.id}"
                case "aggr":
                    name = f"s{switch.pod}a{switch.switch}"
                case "edge":
                    name = f"s{switch.pod}e{switch.switch}"
                case _:
                    print("##########")
                    raise AssertionError(f"Unexpected switch.type: {switch.type}") 
            
            self.addSwitch(name, ip=switch.ip_address)

        # Adding Hosts
        # Host naming convention: "h<h>s<s>p<p>" where h is the host-id, p the pod-id and s the switch-id (ip: 10.p.s.h)
        servers = ft_topo.servers
        for server in servers:
            name = f"h{server.id}s{server.switch}p{server.pod}"
            self.addHost(name, ip=server.ip_address)

        # Adding Links
        edges = ft_topo.edges
        for edge in edges:
            lnode = edge.lnode
            rnode = edge.rnode

            match rnode.type:
                case "serv":
                    assert lnode.type == "edge"
                    lname = f"s{lnode.pod}e{lnode.switch}"
                    rname = f"h{rnode.id}s{rnode.switch}p{rnode.pod}"
                    self.addLink(lname, rname , bw=15, delay="5ms", cls=TCLink)
                case "edge":
                    assert lnode.type == "aggr"
                    lname = f"s{lnode.pod}a{lnode.switch}"
                    rname = f"s{rnode.pod}e{rnode.switch}"
                    self.addLink(lname, rname , bw=15, delay="5ms", cls=TCLink)
                case "aggr":
                    assert lnode.type == "core"
                    lname = f"s{lnode.switch}c{lnode.id}"
                    rname = f"s{rnode.pod}a{rnode.switch}"
                    self.addLink(lname, rname , bw=15, delay="5ms", cls=TCLink)
                case _:
                    raise AssertionError(f"Unexpected rnode.type: {rnode.type}")


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    # mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)
    # _generate_net_graph(net)

    info('*** Starting network ***\n')
    net.start()

    # # Adding IP addresses to switches
    # switches = graph_topo.switches
    # for switch in switches:
    #     match switch.type:
    #         case "core":
    #             name = f"s{switch.switch}c{switch.id}"
    #         case "aggr":
    #             name = f"s{switch.pod}a{switch.switch}"
    #         case "edge":
    #             name = f"s{switch.pod}e{switch.switch}"
    #         case _:
    #             print("##########")
    #             raise AssertionError(f"Unexpected switch.type: {switch.type}") 
    #     s = net.get(name)
    #     s.cmd(f'ifconfig {name} {switch.ip_address}')
    #     # These are not visible in the dump command, but if you run ifconfig on switches you can see them as "inet" entries

    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)
