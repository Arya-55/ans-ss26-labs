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
        self.k = 4
        self.topo_net = topo.Fattree(self.k, do_sanity_check = False)
        self.discovered_pending_ports_on_edge_switch = defaultdict(list[tuple[int, str]]) #dict[dpid] -> (port, IP)

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)-8s %(name)s: %(message)s"))
        self.logger.handlers = []
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        self.logger.debug("BEWARE: Lots of debug messages when host arp caches are empty")

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        common.update_links(self, self.topo_net, [], self.logger)


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


    def add_flow_and_packet_out(self, msg, datapath, in_port, out_port, priority, ip):
        parser = datapath.ofproto_parser

        dpid = datapath.id
        ips_added = []
        # host discovery Part 2: During host discovery, the explored ports do not get a flow rule immediately.
        # When the switch holding the pending ports assigns a flow rule, it will get added to these hosts retroactively
        if dpid in self.discovered_pending_ports_on_edge_switch:
            for (pending_port, pending_ip) in self.discovered_pending_ports_on_edge_switch[dpid]:
                pending_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=pending_ip)
                pending_actions = [parser.OFPActionOutput(pending_port)]
                self.add_flow(datapath=datapath, priority=PRIO_FORWARD_HIGH, match=pending_match, actions=pending_actions)
                self.logger.debug(f"[Discovery 2] add PENDING rule to: out_port={pending_port} | match={pending_match}")
                ips_added.append(pending_ip)
            self.discovered_pending_ports_on_edge_switch[dpid].clear()


        # possibility of duplicate during initial ARP exchange of neighboring hosts where none of the ports were known
        if ip not in ips_added:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath=datapath, priority=priority, match=match, actions=actions)
            self.logger.debug(f"add rule to: out_port={out_port} | match={match}")

        self.logger.debug(f"forward packet to: out_port={out_port}")
        return common.packet_out_to_port(data=msg.data, datapath=datapath, in_port=in_port, port=out_port)
    
    @staticmethod
    def get_output_port_of_upper_node(current_node: topo.Node, dst_host, cur_swi, k):
        # the dispersion of traffic just needs to be deterministic from the perspective of every possible current_node:
        # utilize the IP address of upper layer switch as sorting criteria by turning the IP into an int,
        # which by topology definition should be ordered left to right
        type = "aggr" if current_node.type == "edge" else "core" # edge up to aggr, and aggr up to core

        upper_nodes = [node for node in current_node.neighbors if node.type == type]
        upper_nodes.sort(key=lambda x: int(x.ip_address.replace(".", "")))

        upper_dpid = upper_nodes[((dst_host - 2 + cur_swi) % (k//2))].dpid

        return current_node.ports[upper_dpid]  

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        arp_packet: arp.arp = pkt.get_protocol(arp.arp)
        lldp_packet: lldp.lldp = pkt.get_protocol(lldp.lldp)

        outs = []
        if lldp_packet:
            common.update_links(self, self.topo_net, [], self.logger)
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
            #On ARP receive, look at arp_packet.dst_ip and based on that
            #decide where to route it to, and install flow rule accordingly.
            #the port numbers are taken from the link discovery
            #see the "host discovery" comments in the code for details

            cur_ip = current_node.ip_address
            current_ips = cur_ip.split(".")
            dst_ip = arp_packet.dst_ip
            dst_ips = dst_ip.split(".")

            cur_pod = int(current_ips[1])
            cur_swi = int(current_ips[2])

            dst_pod = int(dst_ips[1])
            dst_sub = int(dst_ips[2])
            dst_host = int(dst_ips[3])

            self.logger.debug(f"{current_node.name} | '{current_node.type}' | cur_ip={cur_ip} | dst_ip={dst_ip}")

            if current_node.type == "edge":
                #controller should ignore dst_ip on edge switches if the host IP does not exist
                if not any(node.ip_address == dst_ip for node in self.topo_net.servers):
                    self.logger.debug("dropped packet, destination not in network")
                    return
                
                # host discovery Part 1: discover in_port link if unexplored
                if in_port in current_node.unexplored_ports:
                    src_node = [node for node in self.topo_net.servers if node.ip_address == arp_packet.src_ip]
                    if src_node:
                        src_node: topo.Node = src_node[0]
                        self.logger.debug(f"[Discovery 1] discover new neighbor at port={in_port} | dpid={src_node.dpid} | ip={src_node.ip_address}")
                        common.discover_link(current_node, src_node.dpid, in_port)
                        self.discovered_pending_ports_on_edge_switch[dpid].append((in_port, src_node.ip_address))

            out_port = None
            priority = None
            ip = None
                        
            if current_node.type == "core":
                # send into pods
                neighbor = [node for node in current_node.neighbors if int(node.ip_address.split(".")[1]) == dst_pod]
                if neighbor:
                    neighbor: topo.Node = neighbor[0]
                    out_port = current_node.ports[neighbor.dpid]
                    ip = f"10.{dst_pod}.0.0/16"
                    priority = PRIO_FORWARD_CORE
            else: #aggr or edge
                if current_node.type == "aggr":
                    if cur_pod == dst_pod:
                        # prefix
                        # inward towards subnets (match first 3 bytes)

                        neighbor = [node for node in current_node.neighbors if node.ip_address.split(".")[0:3] == dst_ips[0:3]]
                        if neighbor:
                            neighbor: topo.Node = neighbor[0]
                            out_port = current_node.ports[neighbor.dpid]
                            ip = f"10.{cur_pod}.{dst_sub}.0/24"
                            priority = PRIO_FORWARD_HIGH
                    else:
                        # suffix
                        # outward towards core

                        out_port = self.get_output_port_of_upper_node(current_node, dst_host, cur_swi, self.k)
                        ip = (f"0.0.0.{dst_host}", "0.0.0.255") #verbose format for suffix specification
                        priority = PRIO_FORWARD_LOW
                else: #edge
                    if cur_swi == dst_sub and cur_pod == dst_pod:
                        # prefix
                        # inward towards hosts directly

                        neighbor = [node for node in current_node.neighbors if node.ip_address == dst_ip]
                        if neighbor:
                            neighbor: topo.Node = neighbor[0]
                            out_port = current_node.ports.get(neighbor.dpid, None) # "safe get" since host may not exist yet
                            ip = dst_ip
                            priority = PRIO_FORWARD_HIGH
                    else:
                        # suffix
                        # outward towards aggr (to other pods or other subnets within pod)

                        out_port = self.get_output_port_of_upper_node(current_node, dst_host, cur_swi, self.k)
                        ip = (f"0.0.0.{dst_host}", "0.0.0.255")
                        priority = PRIO_FORWARD_LOW

                    # host discovery Part Extra: multicast into subnet if out_port unknown (can only be another host) and it's a request
                    if not out_port and arp_packet.opcode == arp.ARP_REQUEST:
                        unexplored_ports = current_node.unexplored_ports
                        self.logger.debug(f"[Discovery Extra] multicast to all unexplored ports {unexplored_ports}")
                        outs.append(common.packet_out_to_ports(data=msg.data, datapath=datapath, in_port=in_port, 
                                                             ports=unexplored_ports))

            if out_port:
                outs.append(self.add_flow_and_packet_out(msg, datapath, in_port, out_port, priority, ip))

        for out in outs:
            self.logger.debug(f"forwarding result={datapath.send_msg(out)}")
