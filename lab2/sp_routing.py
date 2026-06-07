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

from collections import defaultdict
from lib2to3.fixes.fix_renames import alternates
from math import inf

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ether_types, lldp, ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import logging
import topo


PRIO_DROP = 2
PRIO_FORWARD = 1


def print_packet(logger_print_function, packet, dpid):
    logger_print_function(f"Packet on dpid={dpid}:")
    for p in packet.protocols:
        logger_print_function(f" - {p}")


class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)

        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.paths = []  # only for debug logs
        self.setup_paths()

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(name)s: %(message)s"))
        self.logger.handlers = []
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False


    def setup_paths(self):
        for start_node in self.topo_net.servers:
            predecessors = self.dijkstra(start_node)
            for target_node in self.topo_net.servers:
                if start_node.dpid != target_node.dpid:
                    path = self.shortest_path(target_node, predecessors)
                    self.paths.append([hop.dpid for hop in path])
                    self.logger.debug(f"Found path: {[hop.dpid for hop in path]}")
                    self.logger.debug(f"            {[hop.ip_address for hop in path]}")
                    self.logger.debug(f"            {[hop.name for hop in path]}")


    @staticmethod
    def shortest_path(target_node: topo.Node, predecessors: dict[int, topo.Node]) -> list[topo.Node]:
        # https://de.wikipedia.org/wiki/Dijkstra-Algorithmus
        predecessors[target_node.dpid].next_hop[target_node.dpid] = target_node
        path = [target_node]
        current_hop = target_node
        while predecessors[current_hop.dpid]:
            predecessors[current_hop.dpid].next_hop[target_node.dpid] = current_hop
            current_hop = predecessors[current_hop.dpid]
            path = [current_hop] + path
        return path

    def dijkstra(self, start_node: topo.Node):
        # https://de.wikipedia.org/wiki/Dijkstra-Algorithmus
        nodes: list[topo.Node] = [node for node in self.topo_net.switches + self.topo_net.servers]
        distances: dict[int, int] = defaultdict(lambda: inf)  # dpid: distance
        predecessors: dict[int, topo.Node] = defaultdict(lambda: None)
        distances[start_node.dpid] = 0

        while nodes:
            current_hop = min(nodes, key=lambda node: distances[node.dpid])
            nodes.remove(current_hop)
            for neighbor in current_hop.neighbors:
                if neighbor.dpid in map(lambda node: node.dpid, nodes):
                    alternative = distances[current_hop.dpid] + 1
                    if alternative < distances[neighbor.dpid]:
                        distances[neighbor.dpid] = alternative
                        predecessors[neighbor.dpid] = current_hop
        return predecessors

    def update_links(self):
        # Switches and links in the network
        switches = get_switch(self, None)
        links = get_link(self, None)

        for link in links:
            for node in self.topo_net.servers + self.topo_net.switches:
                if link.src.dpid == node.dpid:
                    node.ports[link.dst.dpid] = link.src.port_no  # (5, 6) == (src, dst) --> src.ports[dst] = src.port_no
                    node.unexplored_ports.discard(link.src.port_no)
                elif link.dst.dpid == node.dpid:
                    node.ports[link.src.dpid] = link.dst.port_no
                    node.unexplored_ports.discard(link.dst.port_no)
                if node.dpid in (link.src.dpid, link.dst.dpid):
                    #print(f"AFTER: node.neighbors: {[n.dpid for n in node.neighbors]}")
                    #print(f"AFTER: (node={(node.dpid, node.ip_address, node.name)}, link={(link.src.dpid, link.dst.dpid)}, "
                    #      f"port_no={(link.src.port_no, link.dst.port_no)}), ports={node.ports}")
                    #breakpoint()
                    pass
        for switch in switches:
            node = [node for node in self.topo_net.switches if node.dpid == switch.dp.id]
            if not node:
                self.logger.error(f"openflow switch not found in model: dpid={switch.dp.id}")
                continue
            else:
                node: topo.Node = node[0]

            for port in switch.ports:
                if port.port_no not in node.ports.values():
                    if node.type == "edge" or not any((node.dpid in path for path in self.paths)):
                        node.unexplored_ports.add(port.port_no)
                    else:
                        self.logger.warning(f"non edge switch={(node.dpid, node.ip_address, node.name)} with paths has unexplored port={port}")


    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self.update_links()


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # reduce log noise
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, PRIO_DROP, match, actions)


    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @staticmethod
    def packet_out_to_port(*, data, datapath, in_port, port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        return parser.OFPPacketOut(datapath=datapath,
                                   in_port=in_port,
                                   buffer_id=ofproto.OFP_NO_BUFFER,
                                   actions=[parser.OFPActionOutput(port)],
                                   data=data)

    def flood_packet_out(self, datapath, **kwargs):
        return self.packet_out_to_port(port=datapath.ofproto.OFPP_FLOOD, datapath=datapath, **kwargs)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        eth_frame: ethernet.ethernet = pkt.get_protocol(ethernet.ethernet)
        arp_packet: arp.arp = pkt.get_protocol(arp.arp)
        lldp_packet: lldp.lldp = pkt.get_protocol(lldp.lldp)

        outs = []
        if lldp_packet:
            """self.logger.debug("LLDP Start")
            for tlv in lldp_packet.tlvs:
                self.logger.debug(f"lv={tlv}")
            self.logger.debug("LLDP Stop")"""
            self.update_links()
            return
        else:
            num_minus = 20
            self.logger.debug(num_minus*"-")
            print_packet(self.logger.debug, pkt, dpid)
        if arp_packet:
            current_node = [node for node in self.topo_net.switches if node.dpid == dpid]
            if current_node:
                current_node: topo.Node = current_node[0]
                if current_node.type == "edge":
                    src_node = [node for node in self.topo_net.servers if node.ip_address == arp_packet.src_ip]
                    if src_node:
                        src_node: topo.Node = src_node[0]
                        src_node.mac = arp_packet.src_mac
                        # breakpoint()
                        if src_node.dpid == current_node.next_hop[src_node.dpid].dpid:
                            # if src is directly connected to this edge switch
                            current_node.ports[src_node.dpid] = in_port
                            current_node.unexplored_ports.discard(in_port)
                    else:
                        self.logger.warning(f"could not find src_node for IP {arp_packet.src_ip}")
            else:
                self.logger.error(f"got invalid source IP {arp_packet.src_ip} from dpid={dpid}")
                return
            target_node = [node for node in self.topo_net.servers if node.ip_address == arp_packet.dst_ip]
            if target_node:
                target_node: topo.Node = target_node[0]
                target_node.mac = arp_packet.dst_mac
            else:
                self.logger.error(f"got invalid destination IP {arp_packet.dst_ip} from dpid={dpid}")
                return

            next_hop = current_node.next_hop.get(target_node.dpid)
            if next_hop:
                # breakpoint()
                if next_hop.dpid in current_node.ports:
                    out_port = current_node.ports[next_hop.dpid]
                    outs.append(self.packet_out_to_port(data=msg.data, datapath=datapath, in_port=in_port, port=out_port))
                    self.logger.info(f"dpid={current_node.dpid}: sending arp packet out on port={out_port}")
                else:
                    for out_port in current_node.unexplored_ports:
                        outs.append(self.packet_out_to_port(data=msg.data, datapath=datapath, in_port=in_port, port=out_port))
                    self.logger.warning(f"next port unknown - send to unexplored_ports={current_node.unexplored_ports}")
            else:
                self.logger.error(f"dpid={dpid}: next hop for dpid={target_node.dpid}, ip={target_node.ip_address} not found")
                return
        else:
            current_node = [node for node in self.topo_net.switches if node.dpid == datapath.id]
            if current_node:
                current_node: topo.Node = current_node[0]
            else:
                self.logger.error(f"unknown switch - dpid={dpid}")
                return
            target_node = [node for node in self.topo_net.servers if node.mac == eth_frame.dst]
            if target_node:
                target_node: topo.Node = target_node[0]
            else:
                self.logger.error(f"unknown dst mac {eth_frame.dst} from dpid={dpid}")
                return

            next_hop = current_node.next_hop.get(target_node.dpid)
            if next_hop:
                if next_hop.dpid in current_node.ports:
                    out_port = current_node.ports[next_hop.dpid]
                    outs.append(self.packet_out_to_port(data=msg.data, datapath=datapath, in_port=in_port, port=out_port))
                    self.logger.info(f"dpid={current_node.dpid}: sending ethernet frame out on port={out_port}")

                    match = parser.OFPMatch(in_port=in_port, eth_dst=target_node.mac)
                    actions = [parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath=datapath, priority=PRIO_FORWARD, match=match, actions=actions)
                    self.logger.info(f"dpid={dpid}: added rule: match={match}, actions={actions}")
                else:
                    for out_port in current_node.unexplored_ports:
                        outs.append(self.packet_out_to_port(data=msg.data, datapath=datapath, in_port=in_port, port=out_port))
                    self.logger.warning(f"next port unknown - send to unexplored_ports={current_node.unexplored_ports}")
            else:
                self.logger.error(f"dpid={dpid}: next hop for dpid={target_node.dpid}, ip={target_node.ip_address} not found")
                return

        for out in outs:
            self.logger.debug(f"result={datapath.send_msg(out)}")
