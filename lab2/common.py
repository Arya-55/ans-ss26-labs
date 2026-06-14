"""
Common code shared among sp and ft routing
"""

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

#!/usr/bin/env python3

def print_packet(logger_print_function, packet, dpid, in_port, topo_net: topo.Fattree):
    s = f"Packet on in_port={in_port} dpid={dpid}"
    node = [node for node in topo_net.switches if node.dpid == dpid]
    if node:
        node: topo.Node = node[0]
        s += f" name={node.name}"
    logger_print_function(f"{s}:")
    for p in packet.protocols:
        logger_print_function(f" - {p}")

def discover_link(node: topo.Node, link_dpid, link_port_no):
    node.ports[link_dpid] = link_port_no  # (5, 6) == (src, dst) --> src.ports[dst] = src.port_no
    node.unexplored_ports.discard(link_port_no)

def packet_out_to_port(*, data, datapath, in_port, port):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    return parser.OFPPacketOut(datapath=datapath,
                                in_port=in_port,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                actions=[parser.OFPActionOutput(port)],
                                data=data)

def packet_out_to_ports(*, data, datapath, in_port, ports):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    return parser.OFPPacketOut(datapath=datapath,
                                in_port=in_port,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                actions=[parser.OFPActionOutput(p) for p in ports],
                                data=data)

def update_links(ryu_app, topo_net: topo.Fattree, paths: list, logger):
    # Switches and links in the network
    switches = get_switch(ryu_app, None)
    links = get_link(ryu_app, None)

    for link in links:
        for node in topo_net.servers + topo_net.switches:
            if link.src.dpid == node.dpid:
                discover_link(node, link.dst.dpid, link.src.port_no)
            elif link.dst.dpid == node.dpid:
                discover_link(node, link.src.dpid, link.dst.port_no)
            if node.dpid in (link.src.dpid, link.dst.dpid):
                #print(f"AFTER: node.neighbors: {[n.dpid for n in node.neighbors]}")
                #print(f"AFTER: (node={(node.dpid, node.ip_address, node.name)}, link={(link.src.dpid, link.dst.dpid)}, "
                #      f"port_no={(link.src.port_no, link.dst.port_no)}), ports={node.ports}")
                #breakpoint()
                pass
    for switch in switches:
        node = [node for node in topo_net.switches if node.dpid == switch.dp.id]
        if not node:
            logger.error(f"openflow switch not found in model: dpid={switch.dp.id}")
            continue
        node: topo.Node = node[0]

        for port in switch.ports:
            if port.port_no not in node.ports.values():
                if node.type == "edge" or not any((node.dpid in path for path in paths)):
                    node.unexplored_ports.add(port.port_no)
                else:
                    pass
                    #logger.warning(f"non edge switch={(node.dpid, node.ip_address, node.name)} with paths has unexplored port={port}")
