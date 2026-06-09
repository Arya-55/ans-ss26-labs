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
import common


PRIO_DROP = 100
PRIO_FORWARD_HIGH = 2
PRIO_FORWARD_LOW = 1
PRIO_FORWARD_CORE = 1


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4, do_sanity_check = False)
        self.paths = []  # only for debug logs

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(name)s: %(message)s"))
        self.logger.handlers = []
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        common.update_links(self, self.topo_net, self.paths, self.logger)


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
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
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


    def add_flow_and_packet_out(self, msg, datapath, in_port, out_port, priority, ip):
        parser = datapath.ofproto_parser
        #TODO is this sufficient matches?
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath=datapath, priority=priority, match=match, actions=actions)

        print(f"add rule+forward to: {ip} on out_port={out_port} | match={match}")
        current_node = [node for node in self.topo_net.switches if node.dpid == datapath.id]
        if current_node:
            current_node : topo.Node = current_node[0]
            print(f"{str(current_node.ports)}") #TODO debug
            next_node_ids = [k for k, v in current_node.ports.items() if v == out_port]
            if next_node_ids:
                next_node_id = next_node_ids[0]
                print(f"{str([node.name for node in current_node.neighbors])}") #TODO debug
                next_node = [node for node in current_node.neighbors if node.dpid == next_node_id]
                if next_node:
                    next_node : topo.Node = next_node[0]
                    print(f"from {current_node.name} towards: {next_node.name}")
            else: print("no host neighbor exists")

        return self.packet_out_to_port(data=msg.data, datapath=datapath, in_port=in_port, port=out_port)

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
            common.update_links(self, self.topo_net, self.paths, self.logger)
            return
        else:
            num_minus = 20
            self.logger.debug(num_minus*"-")
            common.print_packet(self.logger.debug, pkt, dpid, in_port, self.topo_net)

        current_node = [node for node in self.topo_net.switches if node.dpid == dpid]
        if not current_node:
            return
        current_node: topo.Node = current_node[0]
        
        if arp_packet:
            if current_node.type == "edge":
                src_node = [node for node in self.topo_net.servers if node.ip_address == arp_packet.src_ip]
                if src_node:
                    src_node: topo.Node = src_node[0]
                    # remember source mac
                    src_node.mac = arp_packet.src_mac
                    # breakpoint()
                    #if src_node.dpid == current_node.next_hop[src_node.dpid].dpid:
                        # if src is directly connected to this edge switch
                        #current_node.ports[src_node.dpid] = in_port
                        #current_node.unexplored_ports.discard(in_port)
                else:
                    self.logger.warning(f"could not find src_node for IP {arp_packet.src_ip}")
            
            #On ARP receive, look at arp_packet.dst_ip and based on that
            #decide where to route it to, and install flow rule accordingly
            #use the port numbers assumed from the topology

            k = 4
            cur_ip = current_node.ip_address
            current_ips = cur_ip.split(".")
            dst_ip = arp_packet.dst_ip
            dst_ips = dst_ip.split(".")

            cur_pod = int(current_ips[1])
            cur_swi = int(current_ips[2])

            dst_pod = int(dst_ips[1])
            dst_sub = int(dst_ips[2])
            dst_host = int(dst_ips[3])

            print(f"{current_node.name} | '{current_node.type}' | cur_ip={cur_ip} | dst_ip={dst_ip}")

            if current_node.type == "core":
                out_port = dst_pod + 1
                ip_prefix = f"10.{dst_pod}.0.0/16"

                outs.append(self.add_flow_and_packet_out(msg, datapath, in_port, out_port, PRIO_FORWARD_CORE, ip_prefix))
            else: #aggr or edge
                if current_node.type == "aggr":
                    if cur_pod == dst_pod:
                        #prefix
                        #inward towards subnets
                        out_port = dst_sub + 1
                        ip_prefix = f"10.{cur_pod}.{dst_sub}.0/24"

                        outs.append(self.add_flow_and_packet_out(msg, datapath, in_port, out_port, PRIO_FORWARD_HIGH, ip_prefix))
                    else:
                        #suffix
                        #outward towards core
                        out_port = ((dst_host - 2 + cur_swi) % (k//2)) + (k//2) + 1
                        ip_suffix = (f"0.0.0.{dst_host}", "0.0.0.255") #verbose format for suffix specification

                        outs.append(self.add_flow_and_packet_out(msg, datapath, in_port, out_port, PRIO_FORWARD_LOW, ip_suffix))
                else: #edge
                    if cur_swi == dst_sub and cur_pod == dst_pod:
                        #prefix
                        #inward towards hosts/servers
                        out_port = dst_host - 2 + 1
                        ip_prefix = dst_ip

                        outs.append(self.add_flow_and_packet_out(msg, datapath, in_port, out_port, PRIO_FORWARD_HIGH, ip_prefix))
                    else:
                        #suffix
                        #outward towards aggr (to other pods or other subnets witin pod)
                        #same calculations and IP as aggr outwards
                        out_port = ((dst_host - 2 + cur_swi) % (k//2)) + (k//2) + 1
                        ip_suffix = (f"0.0.0.{dst_host}", "0.0.0.255")

                        outs.append(self.add_flow_and_packet_out(msg, datapath, in_port, out_port, PRIO_FORWARD_LOW, ip_suffix))

        for out in outs:
            self.logger.debug(f"result={datapath.send_msg(out)}")
