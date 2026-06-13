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
    number1 = int(ident1[1:])
    number2 = int(ident2[1:])
    
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
                return number1 < number2
        else:
            # switch 
            if not ident2.startswith("s"):
                # compared to host
                return True
            else:
                # compared to another switch
                return number1 < number2


def _sort_node_layers(pos, graph):
    names = list(pos.keys())
    coordinates = list(pos.values())

    for i in range(len(names)):
        for j in range(len(names) - i - 1):
            name1 = names[j]
            coordinates1 = coordinates[j]

            name2 = names[j + 1]
            coordinates2 = coordinates[j + 1]

            if _lt(name2, name1):
                if not graph.nodes[name1]["layer"] == graph.nodes[name2]["layer"]: 
                    # do not sort between layers
                    continue

                #comparison within layer: compare x - coordinates
                if coordinates2[1] < coordinates1[1]:
                    # x - coordinates of names do fit order of names -> switch together with names
                    coordinates[j], coordinates[j + 1] = coordinates[j + 1], coordinates[j]

                # switch names
                names[j], names[j + 1] = names[j + 1], names[j]

    # Built new pos dict
    sorted_pos = {}
    for i in range(len(names)):
        sorted_pos[names[i]] = coordinates[i]
    
    return sorted_pos


def _generate_net_graph(net, graph_topo):
    k = graph_topo.k
    graph = nx.Graph()

    for s in net.switches:
        switch_type = [ts.type for ts in graph_topo.switches if ts.name == s.name][0]
        
        match switch_type:
            case "core":
                layer = 3
            case "aggr":
                layer = 2
            case "edge":
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
            switch_type = [ts.type for ts in graph_topo.switches if ts.name == name][0]
            if switch_type == "core":
                pos[name] = [coordinates[0] * k/2, coordinates[1] * 1.5]
            else:
                pos[name] = [coordinates[0] * k/2, coordinates[1]]
    pos = _sort_node_layers(pos, graph)

    # this value is carefully tried and errored to make the graph look nice ":D
    fig_width = int((np.round(np.sqrt(300/np.pi))) + 50 / 72 * len(net.hosts))   # diameter of graph node with padding / 72 ppi * number of hosts
    fig = plt.figure(figsize=(fig_width, 10))
    ax = plt.gca()
    
    # draw hosts
    nx.draw_networkx_nodes(
        graph, 
        pos,
        nodelist=[h.name for h in net.hosts],
        node_shape='o',
        node_color = "navajowhite", 
        node_size=1400
    )
    # draw switches
    nx.draw_networkx_nodes(
        graph, 
        pos,
        nodelist=[s.name for s in net.switches],
        node_shape='o',
        node_color = "lightskyblue", 
        node_size=1400
    )
    # draw edges between nodes
    nx.draw_networkx_edges(graph, pos, width=1)
    # draw node names
    nx.draw_networkx_labels(graph, pos, font_size=9, font_weight="bold")

    # build positions and labels for ip addresses
    ip_pos = pos.copy()
    for key in ip_pos:
        ip_pos[key][1] = ip_pos[key][1] - 0.03 * k

    ip_labels = {}
    for key, value in graph.nodes(data=True):
        ip_labels[key] = value["ip"]

    # draw ip labels
    nx.draw_networkx_labels(graph, ip_pos, labels=ip_labels, font_size=7)

    # draw rectangles for pods:
    fst_edge = int(5*k*k/4 - k * k/2 + 1)                                   # number of all switches - k * k/2
    fst_aggr = int((k/2)**2 + 1)                                            # number of core switches + 1
    width = pos[f"s{fst_edge + int(k/2) - 1}"][0] - pos[f"s{fst_edge}"][0]  # distance between first edge switch and last edge switch in first pod
    height = pos[f"s{fst_aggr}"][1] - pos[f"s{fst_edge}"][1]                # distance between first edge switch and first aggr switch in first pod
    for i in range(k):
        x, y = pos[f"s{fst_edge + int(i * k/2)}"]                           # switch position on bottom left of each pod
        xmargin = 0.15 * k
        ymargin = 0.1 * k 
        rect = Rectangle(
            (x - xmargin, y - ymargin/1.5), 
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
    fig.savefig(f"./artifacts/topology_{k}-port.png", dpi=300, bbox_inches="tight")


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)
        
        # Adding Switches
        switches = ft_topo.switches
        for s in switches:
            # print(f"Switch: {(s.name, s.ip_address, s.dpid)}")
            self.addSwitch(s.name, ip=s.ip_address)

        # Adding Hosts
        hosts = ft_topo.servers
        for h in hosts:
            # print(f"Host: {(h.name, h.ip_address, h.dpid)}")
            self.addHost(h.name, ip=h.ip_address)

        # Adding Links
        edges = ft_topo.edges
        for edge in edges:
            # print((edge.lnode.name, edge.rnode.name), (edge.lnode.dpid, edge.rnode.dpid), (edge.lnode.ip_address, edge.rnode.ip_address))
            self.addLink(edge.lnode.name, edge.rnode.name , bw=15, delay="5ms", cls=TCLink)

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
    _generate_net_graph(net, graph_topo)

    for host in net.hosts:  # reduce log noise
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        host.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    info('*** Starting network ***\n')
    net.start()

    # Experiment for 4-port Switches
    if graph_topo.k == 4:
        net.pingAll()

        # left most hosts
        h21 = net.get("h21")
        h22 = net.get("h22")

        # right most hosts - in a different pod
        h35 = net.get("h35")
        h36 = net.get("h36")

        #with open("./artifacts/sp_result.txt", "w") as f:
        with open("./artifacts/ft_result.txt", "w") as f:
            for prot in ["", "-u -b 15M"]: # TCP, UDP (with link rate)
                if len(prot) > 0:
                    print("\nRunning iperf experiment for UDP connection")
                    f.write("===== UDP =====\n")
                else:
                    print("\nRunning iperf experiment for TCP connection")
                    f.write("===== TCP =====\n")
                
                f.write("=== Exp 1 ===\n")                
                # set up single communication h21 <-> h35 between hosts in different pods  
                h21_listener = h21.popen(f'iperf -s {prot}')
                h35_proc = h35.popen(f'iperf -c {h21.IP()} -t 20 {prot}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # get results and write them down
                h35_out, h35_err = h35_proc.communicate()
                print(h35_out, h35_err)
                f.write(f"{h35_out}{h35_err}")

                f.write("=== Exp 2 ===\n")
                # set up simultaneous communication between all hosts of two edge switches in different pods (h21 <-> h35, h22 <-> h36) 
                h21_listener = h21.popen(f'iperf -s {prot}')
                h22_listener = h22.popen(f'iperf -s {prot}')
                h35_proc = h35.popen(f'iperf -c {h21.IP()} -t 20 {prot}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                h36_proc = h36.popen(f'iperf -c {h22.IP()} -t 20 {prot}', stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # get outputs and write them down
                h35_out, h35_err = h35_proc.communicate()
                h36_out, h36_err = h36_proc.communicate()
                print(h35_out, h35_err)
                print(h36_out, h36_err)
                f.write(f"{h35_out}{h35_err}")
                f.write(f"{h36_out}{h36_err}")

                # shut down server processes
                h21_listener.terminate()
                h22_listener.terminate()
                print("Experiment finished")

    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)