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
from typing import Dict, List
import re

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
from matplotlib.patches import Rectangle
import numpy as np

import topo

def _lt(ident1:str, ident2:str):
    numbers1 = []
    numbers2 = []
    
    if ident1 == ident2:
        return False
    else:
        if ident1.startswith("h"):
            # host
            if not ident2.startswith("h"):
                # compared to switch
                return False
            else:
                # compared to another host
                numbers1 = re.findall(r"\d", ident1)
                numbers2 = re.findall(r"\d", ident2)
                numbers1.reverse()
                numbers2.reverse()
        else:
            # switch 
            if not ident2.startswith("s"):
                # compared to host
                return True
            else:
                # compared to another switch
                numbers1 = re.findall(r"\d", ident1)
                numbers2 = re.findall(r"\d", ident2)
    
    for i in range(len(numbers1)):
        if numbers1[i] == numbers2[i]:
            continue
        else:
            return numbers1[i] < numbers2[i]


def _sort_node_positions(pos):
    names = list(pos.keys())
    coordinates = list(pos.values())
    
    for i in range(len(names)):
        for j in range(len(names) - i - 1):
            name1 = names[j]
            coordinates1 = coordinates[j]
            letters1 = "".join(re.findall(r"[a-z]", name1))

            name2 = names[j + 1]
            coordinates2 = coordinates[j + 1]
            letters2 = "".join(re.findall(r"[a-z]", name2))

            if _lt(name2, name1):
                if letters1 == letters2:
                    # comparison within layer: compare x - coordinates
                    if coordinates2[1] < coordinates1[1]:
                        # coordinates of names do fit order of names -> switch together with names
                        coordinates[j], coordinates[j + 1] = coordinates[j + 1], coordinates[j]
                else:
                    # comparisons between layers -> always switch name and coordinates
                    coordinates[j], coordinates[j + 1] = coordinates[j + 1], coordinates[j]

                # switch names
                names[j], names[j + 1] = names[j + 1], names[j]      

    # Built new pos dict
    sorted_pos = {}
    for i in range(len(names)):
        sorted_pos[names[i]] = coordinates[i]
    
    return sorted_pos


def _generate_net_graph(net, k):
    graph = nx.Graph()

    for s in net.switches:
        if "c" in s.name:
            layer = 3
        if "a" in s.name:
            layer = 2
        if "e" in s.name:
            layer = 1

        graph.add_node(s.name, type = "switch", ip = s.params.get("ip"))
        graph.nodes[s.name]["layer"] = layer

    for h in net.hosts:
        graph.add_node(h.name, type = "host", ip = h.IP())
        graph.nodes[h.name]["layer"] = 0

    for l in net.links:
        lnode = l.intf1.node.name
        rnode = l.intf2.node.name
        graph.add_edge(lnode, rnode)

    pos = nx.multipartite_layout(graph, subset_key="layer", align="horizontal", scale=len(net.hosts))
    for name, coordinates in pos.items():
        if name.startswith("s"):
            if "c" in name:
                pos[name] = [coordinates[0] * k/2, coordinates[1] * 1.5]
            else:
                pos[name] = [coordinates[0] * k/2, coordinates[1]]
    pos = _sort_node_positions(pos)

    # this value is carefully tried and errored to make the graph look nice for ":D
    fig_width = int((np.round(np.sqrt(300/np.pi))) + 50 / 72 * len(net.hosts))   # diameter of graph node with padding / 72 ppi * number of hosts
    fig = plt.figure(figsize=(fig_width, 10))
    ax = plt.gca()
    
    # draw graph
    nx.draw_networkx_nodes(
        graph, 
        pos,
        nodelist=graph.nodes,
        node_shape='o',
        node_size=1300
    )
    nx.draw_networkx_edges(graph, pos, width=1)
    nx.draw_networkx_labels(graph, pos, font_size=9)

    # draw rectangles for pods:
    width = pos[f"s0e{int(k/2)-1}"][0] - pos["s0e0"][0]
    height = pos[f"s0a{int(k/2)}"][1] - pos["s0e0"][1]
    for i in range(k):
        x, y = pos[f"s{i}e0"]                       # switch position on upper left of pod
        xmargin = 0.15 * k
        ymargin = 0.1 * k 
        rect = Rectangle(
            (x - xmargin, y - ymargin), 
            width = abs(width) + 2*xmargin, 
            height = abs(height) + 2*ymargin,
            edgecolor="red",
            facecolor="none",
            linewidth=2)
        ax.add_patch(rect)

    plt.title(f"Generated Fatnet Topology (num_ports={k})", fontsize=20)
    plt.margins(0)
    xmin = min(np.array(list(pos.values()))[:,0]) - 1
    xmax = max(np.array(list(pos.values()))[:,0]) + 1
    plt.xlim(xmin, xmax)
    ax.set_axis_off()
    fig.savefig(f"topology_{k}-port.png", dpi=300, bbox_inches="tight")


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
        for i, switch in enumerate(switches, start=1):
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
            
            self.addSwitch(name, ip=switch.ip_address, dpid=f"{i:016d}")

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
    _generate_net_graph(net, k=graph_topo.k)

    for host in net.hosts:  # reduce log noise
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)
