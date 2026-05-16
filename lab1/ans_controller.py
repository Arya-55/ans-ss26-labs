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
<<<<<<< Updated upstream
=======
from collections import defaultdict
from copy import deepcopy
from dataclasses import asdict, dataclass
from ipaddress import ip_address, ip_network, IPv4Network, IPv4Address
from logging import getLogger, StreamHandler, Formatter
>>>>>>> Stashed changes

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
<<<<<<< Updated upstream
from ryu.ofproto import ofproto_v1_3
=======
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, in_proto, icmp, arp
from ryu.ofproto import ofproto_v1_3, ether
from pprint import pprint, pformat
from typing import Union


logger, switch_logger = getLogger(__name__), getLogger(__name__)
loglevel = "DEBUG"
logger, switch_logger = getLogger(f"{__name__}_Router"), getLogger(f"{__name__}_Switch")
logger.propagate, switch_logger.propagate = False, False
logger.setLevel(loglevel), switch_logger.setLevel("INFO")
logger.handlers.clear(), switch_logger.handlers.clear()
handler = StreamHandler()
switch_log_handler = StreamHandler()
handler.setFormatter(Formatter(fmt="%(asctime)s, %(name)s, %(levelname)s, %(lineno)d: %(message)s"))
switch_log_handler.setFormatter(Formatter(fmt="%(asctime)s, %(name)s, %(levelname)s, %(lineno)d: %(message)s"))
logger.addHandler(handler)
# switch_logger.addHandler(switch_log_handler)


PRIO_FIREWALL = 5
PRIO_DROP = 4
PRIO_REPLY = 3
PRIO_FORWARD = 2
PRIO_CATCHALL = 0
>>>>>>> Stashed changes


# Router port MACs assumed by the controller
port_to_own_mac = {
    1: "00:00:00:00:01:01",
    2: "00:00:00:00:01:02",
    3: "00:00:00:00:01:03"
}

# Router port (gateways) IP addresses assumed by the controller
port_to_own_ip = {
    1: "10.0.1.1",          # internal host gateway (s1 subnet)
    2: "10.0.2.1",          # internal server gateway (ser)
    3: "192.168.1.1"        # external server gateway (ext)
}

netmask = "255.255.255.0"
network_to_port = {ip_network((ip, netmask), strict=False).network_address: port for port, ip in port_to_own_ip.items()}


def packet_out_to_port(*, data, datapath, parser, in_port, port, ofproto):
    return parser.OFPPacketOut(datapath=datapath,
                               in_port=in_port,
                               buffer_id=ofproto.OFP_NO_BUFFER,
                               actions=[parser.OFPActionOutput(port)],
                               data=data)


def reply_packet_to_in_port(*, in_port, ofproto, **kwargs):
    return packet_out_to_port(port=in_port, in_port=ofproto.OFPP_CONTROLLER, ofproto=ofproto,  **kwargs)


def flood_packet_out( *, ofproto, **kwargs):
    return packet_out_to_port(port=ofproto.OFPP_FLOOD, ofproto=ofproto, **kwargs)


def send_destination_unreachable(pkt, datapath, parser, in_port, ofproto, type_=icmp.ICMP_DEST_UNREACH, code=13):
    router_mac = port_to_own_mac[in_port]
    router_ip = port_to_own_ip[in_port]

    eth_packet = pkt.get_protocol(ethernet.ethernet)
    ipv4_packet = pkt.get_protocol(ipv4.ipv4)

    # extra stuff for ICMP unreachable that is not natively supported by the library
    eth_offset = 14
    if eth_packet.ethertype == ether.ETH_TYPE_8021Q:
        eth_offset = eth_offset + 4

    orig_data = pkt.data[eth_offset:eth_offset + ipv4_packet.header_length * 4 + 8]
    # helper for icmp payload
    icmp_data = icmp.dest_unreach(data_len=len(orig_data), data=orig_data)

    un_pkt = packet.Packet()
    un_pkt.add_protocol(ethernet.ethernet(src=router_mac, dst=eth_packet.src, ethertype=ether.ETH_TYPE_IP))
    un_pkt.add_protocol(ipv4.ipv4(src=router_ip, dst=ipv4_packet.src, proto=in_proto.IPPROTO_ICMP))
    un_pkt.add_protocol(icmp.icmp(type_=type_, code=code, csum=0, data=icmp_data))
    un_pkt.serialize()
    logger.info(f"\n\nSEND ICMP UNREACHABLE:\n {str(un_pkt)}")
    logger.info(f"\nin_port: {in_port}") # Easier to notice, before it was 2, then 1 after pingall
    # outdated with the controller redirect actions taking priority: TODO after pingall (router populated with flow rules), "ext ping h1 -c1" no longer instantly breaks, however,
    # "h1 ping ext -c1" works (hosts swapped). The reason is that since the ping goes back and forth, it gets blocked on the h1 side, meaning the ext one hangs
    # so this means the rules for ext in the router let it through somehow after pingall, even if it should go through the firewall check here
    return reply_packet_to_in_port(data=un_pkt.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)


@dataclass
class FirewallForward:
    proto: int
    src: IPv4Network
    dst: IPv4Network

    def match(self, pkt):
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        return all((ipv4_packet.proto,
                    ip_network((ipv4_packet.src, netmask), strict=False) == self.src,
                    ip_network((ipv4_packet.dst, netmask), strict=False) == self.dst))

    @staticmethod
    def ofp_match(pkt, parser):
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        return parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=ipv4_packet.proto, ipv4_src=ipv4_packet.src, ipv4_dst=ipv4_packet.dst)

    def actions(self, eth_src, eth_dst, parser):
        out_port = network_to_port[self.dst.network_address]
        return [parser.OFPActionSetField(eth_src=eth_src),
                parser.OFPActionSetField(eth_dst=eth_dst),
                parser.OFPActionDecNwTtl(),
                parser.OFPActionOutput(out_port)]

    def first_packet(self, pkt, eth_dst, datapath, parser, in_port, ofproto):
        eth_packet = pkt.get_protocol(ipv4.ipv4)
        out_port = network_to_port[self.dst.network_address]
        eth_packet.src = port_to_own_mac[out_port]
        eth_packet.dst = eth_dst
        eth_packet.ethertype = ether_types.ETH_TYPE_IP
        pkt.serialize()
        return packet_out_to_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, port=out_port, ofproto=ofproto)


@dataclass
class FirewallICMPResponse:
    proto: int
    src: IPv4Network
    dst: IPv4Network
    types: list[int]

    def match(self, pkt):
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        icmp_packet = pkt.get_protocol(icmp.icmp)
        return all((ipv4_packet.proto,
                    ip_network((ipv4_packet.src, netmask), strict=False) == self.src,
                    ip_network((ipv4_packet.dst, netmask), strict=False) == self.dst,
                    icmp_packet.type in self.types))

    @staticmethod
    def actions(parser, ofproto):
        return [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

    @staticmethod
    def first_packet(pkt, datapath, parser, in_port, ofproto):
        return send_destination_unreachable(pkt=pkt, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
<<<<<<< Updated upstream
        
=======
        self.packet_counter = 0
        self.mac_to_port = defaultdict(dict)
        self.ip_to_mac = {}
        self.buffered_msgs = defaultdict(list)
        self.same_network_arp_drop_rules = defaultdict(list)
        self.same_network_ip_drop_rules = defaultdict(list)

        self.firewall_exceptions = {
            in_proto.IPPROTO_ICMP: [
                FirewallICMPResponse(in_proto.IPPROTO_ICMP, ip_network("10.0.0.0/16"), ip_network("192.168.1.0/24"),
                                     [icmp.ICMP_ECHO_REQUEST, icmp.ICMP_ECHO_REPLY])
            ],
            in_proto.IPPROTO_TCP: [
                FirewallForward(in_proto.IPPROTO_TCP, ip_network("10.0.1.0/24"), ip_network("192.168.1.0/24")),
                FirewallForward(in_proto.IPPROTO_TCP, ip_network("192.168.1.0/24"), ip_network("10.0.1.0/24")),
                FirewallForward(in_proto.IPPROTO_TCP, ip_network("10.0.1.0/24"), ip_network("10.0.2.0/24")),
                FirewallForward(in_proto.IPPROTO_TCP, ip_network("10.0.2.0/24"), ip_network("10.0.1.0/24"))
            ],
            in_proto.IPPROTO_UDP: [
                FirewallForward(in_proto.IPPROTO_UDP, ip_network("10.0.1.0/24"), ip_network("192.168.1.0/24")),
                FirewallForward(in_proto.IPPROTO_UDP, ip_network("192.168.1.0/24"), ip_network("10.0.1.0/24")),
                FirewallForward(in_proto.IPPROTO_UDP, ip_network("10.0.1.0/24"), ip_network("10.0.2.0/24")),
                FirewallForward(in_proto.IPPROTO_UDP, ip_network("10.0.2.0/24"), ip_network("10.0.1.0/24"))
            ]
        }

        self.firewall_tracked = []

>>>>>>> Stashed changes

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath

<<<<<<< Updated upstream
        # Your controller implementation should start here
=======
        pkt = packet.Packet(msg.data)
        for p in pkt.protocols:
            switch_logger.info(f" - {p}")

        if datapath.id == 3:
            # handle router (s3) request
            logger.info(f"\n###### NEW PACKET (Router) ######")
            self.handle_router_request(ev)
        else:
            # handle switch requests
            switch_logger.info(f"\n###### NEW PACKET (Switch) ######")
            num_minus = 10
            print(num_minus * "-" + "Switch Request start (_packet_in_handler)" + num_minus * "-")
            
            in_port = msg.match["in_port"]
            pkt = packet.Packet(msg.data)

            switch_logger.info("Switch Packets:")
            for p in pkt.protocols:
                switch_logger.info(f"\t- {p}")

            eth = pkt.get_protocol(ethernet.ethernet)
            switch_logger.info(f"seq={self.packet_counter}: dpid={datapath.id}: in_port={in_port}, eth_src={eth.src}, eth_dst={eth.dst};")

            if not self.mac_to_port.get(datapath.id, {}).get(eth.src):
                # learn mapping between input-port and its MAC address (eth.src)
                self.mac_to_port[datapath.id][eth.src] = in_port
                switch_logger.info(f"Updated mac_to_port for s{datapath.id}, {self.mac_to_port[datapath.id]}")
            else: 
                switch_logger.info("Already know in_port <-> MAC-address mapping")

            out_port = self.mac_to_port.get(datapath.id, {}).get(eth.dst)
            if out_port:
                # controller knows port of non-broadcast destination MAC -> add flow rule matching on in_port and dst-MAC
                match = parser.OFPMatch(eth_dst = eth.dst, in_port = in_port)
                actions = [parser.OFPActionOutput(port=out_port)]
                self.add_flow(datapath=datapath, priority=PRIO_FORWARD, match=match, actions=actions)
                switch_logger.info(f"Added rule on s{datapath.id}: match={match}, action={actions}")
                
                # send packet out to output port
                out = packet_out_to_port(data=msg.data, datapath=datapath, parser=parser, in_port=in_port, port=out_port, ofproto=ofproto)
                switch_logger.info(f"Instruction to dpid={datapath.id}: Send out to port {out_port}")
            else:
                # Flood packet out
                out = flood_packet_out(data=msg.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)
                switch_logger.info(f"Instruction to dpid={datapath.id}: broadcast")

            datapath.send_msg(out)

    def check_firewall_exceptions(self, pkt) -> Union[FirewallForward, FirewallICMPResponse, None]:
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        for exception in self.firewall_exceptions[ipv4_packet.proto]:
            if exception.match(pkt):
                return exception
        return None

    def forward_ipv4_packet(self, datapath, data, in_port, eth_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(data)
        logger.debug(f"Function forward_ipv4_packet(): Protocols:")
        for p in pkt.protocols:
            logger.debug(f"\t- {p}")

        exception = self.check_firewall_exceptions(pkt)
        if not exception:
            return None

        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        ipv4_packet.ttl = ipv4_packet.ttl - 1

        match = exception.ofp_match(pkt=pkt, parser=parser)
        dst_network = exception.dst
        out_port = network_to_port[dst_network.network_address]
        actions = exception.actions(eth_src=port_to_own_mac[out_port], eth_dst=eth_dst, parser=parser)
        self.add_flow(datapath=datapath, priority=PRIO_FORWARD, match=match, actions=actions)
        logger.debug(f"Added rule: match={match}, actions={actions} on router;")
        return exception.first_packet(pkt=pkt, eth_dst=eth_dst, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)


    def construct_arp_request(self, port, dst_ip, datapath, parser, ofproto):
        eth_packet = ethernet.ethernet(src=self.port_to_own_mac[port], ethertype=ether_types.ETH_TYPE_ARP)
        arp_packet = arp.arp(opcode=arp.ARP_REQUEST, src_mac=port_to_own_mac[port], src_ip=port_to_own_ip[port], dst_mac="00:00:00:00:00:00", dst_ip=dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth_packet)
        pkt.add_protocol(arp_packet)
        pkt.serialize()

        logger.info(f"construct arp request, contents:")
        for p in pkt.protocols:
            logger.info(f"> {p}")

        logger.info(f"arp request for {dst_ip}")
        return packet_out_to_port(data=pkt.data, datapath=datapath, parser=parser, in_port=ofproto.OFPP_CONTROLLER, port=port, ofproto=ofproto)


    def handle_router_request(self, ev):
        num_minus = 10
        logger.debug(num_minus * "-" + "Router Request start (handle_router_request)" + num_minus * "-")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        icmp_packet = pkt.get_protocol(icmp.icmp)
        arp_packet = pkt.get_protocol(arp.arp)

        outs = []

        if arp_packet:
            logger.info(f"seq={self.packet_counter}: Got ARP packet:\n{arp_packet}")

            if arp_packet.dst_ip != port_to_own_ip[in_port]: # not directed to gateway: internal ARP, drop
                if arp_packet.dst_ip not in self.same_network_arp_drop_rules[in_port]:
                    logger.info("got foreign arp request. Dropping.")
                    match = parser.OFPMatch(in_port=in_port, arp_tpa=arp_packet.dst_ip, eth_type=ether_types.ETH_TYPE_ARP)
                    self.add_flow(datapath=datapath, priority=PRIO_DROP, match=match, actions=[])
                    logger.debug(f"Added rule: match={match}, actions={[]} on router;")
                    self.same_network_arp_drop_rules[in_port].append(arp_packet.dst_ip)
                else:
                    logger.error(f"Existing arp drop rule did not match: in_port={in_port} dst_ip={arp_packet.dst_ip}")
            elif arp_packet.opcode == arp.ARP_REPLY:  # process arp reply
                logger.info("got ARP Reply")
                self.ip_to_mac[arp_packet.src_ip] = arp_packet.src_mac
                if self.buffered_msgs[arp_packet.src_ip]:
                    logger.info("found buffered IP packets, forwarding...")
                    buffered = self.buffered_msgs[arp_packet.src_ip].pop(0)
                    logger.debug(f"popped from buffer: {pformat(buffered)}")
                    outs.append(self.forward_ipv4_packet(eth_dst=arp_packet.src_mac, **buffered))
            else:  # reply to arp request
                logger.info("Found ARP Request")
                if eth_packet.src != self.ip_to_mac.get(arp_packet.src_ip):
                    logger.info(f"Found new IP-MAC pair: {arp_packet.src_ip} -> {eth_packet.src}")
                    self.ip_to_mac[arp_packet.src_ip] = eth_packet.src

                # send arp reply manually
                eth_packet.src, eth_packet.dst = port_to_own_mac[in_port], eth_packet.src
                arp_packet.src_mac, arp_packet.dst_mac = port_to_own_mac[in_port], arp_packet.src_mac
                arp_packet.src_ip, arp_packet.dst_ip = port_to_own_ip[in_port], arp_packet.src_ip
                arp_packet.opcode = arp.ARP_REPLY
                pkt = packet.Packet()
                pkt.add_protocol(eth_packet)
                pkt.add_protocol(arp_packet)
                pkt.serialize()
                
                logger.debug(f"construct arp reply, contents:")
                for p in pkt.protocols:
                    logger.debug(f"> {p}")
                
                outs.append(reply_packet_to_in_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto))
                logger.info(f"Instruction: send arp reply")

        if ipv4_packet:
            logger.info(f"seq={self.packet_counter}: Got IPv4 packet")
            logger.debug(f"ipv4_packet: {ipv4_packet.src} -> {ipv4_packet.dst}; eth_packet: {eth_packet.src} -> {eth_packet.dst};")

            firewall_entry = self.check_for_firewall_entry(ipv4_packet, icmp_packet=icmp_packet)

            if firewall_entry:
                if firewall_entry not in self.firewall_tracked:
                    self.firewall_tracked.append(firewall_entry)

                    # There is an entry in the firewall-table fitting this packet
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, **firewall_entry)

                    # if icmp, redirect back to controller so it can send icmp unreachable
                    actions = []
                    if icmp_packet:
                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                    self.add_flow(datapath=datapath, priority=PRIO_FIREWALL, match=match, actions=actions)
                    logger.info(f"Added firewall rule on router: match={match}, action={actions}")

                # Send a "Destination Unreachable - Communication Administratively Prohibited" ICMP
                # If it was an ICMP packet
                if icmp_packet:
                    outs.append(send_destination_unreachable(pkt, eth_packet, ipv4_packet, datapath, parser, in_port, ofproto))

            else:
                logger.debug(f"self.ip_to_mac={self.ip_to_mac}")
                if eth_packet.src != self.ip_to_mac.get(ipv4_packet.src):
                    logger.info(f"Found new IP-MAC pair: {ipv4_packet.src} -> {eth_packet.src}")
                    self.ip_to_mac[ipv4_packet.src] = eth_packet.src
                # IP forwarding
                if ipv4_packet.dst in port_to_own_ip.values():
                    if ipv4_packet.proto == in_proto.IPPROTO_ICMP:
                        logger.info(f"ping Gateway: src={ipv4_packet.src}; dst={ipv4_packet.dst};")
                        eth_packet.src, eth_packet.dst = port_to_own_mac[in_port], eth_packet.src
                        ipv4_packet.src, ipv4_packet.dst = port_to_own_ip[in_port], ipv4_packet.src
                        icmp_packet.type = icmp.ICMP_ECHO_REPLY
                        pkt = packet.Packet()
                        pkt.add_protocol(eth_packet)
                        pkt.add_protocol(ipv4_packet)
                        pkt.add_protocol(icmp_packet)
                        pkt.serialize()
                        outs.append(reply_packet_to_in_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto))
                        logger.info(f"Instruction: send icmp echo reply")
                    else:
                        logger.error(f"unknown IP-Protocol: {ipv4_packet.proto}")

                elif (ip_network((ipv4_packet.src, netmask), strict=False) == ip_network((ipv4_packet.dst, netmask), strict=False) and
                        ipv4_packet.dst != port_to_own_ip[in_port]):
                    if ipv4_packet.dst not in self.same_network_ip_drop_rules[in_port]:
                        logger.info("got in network ip broadcast. Dropping.")
                        match = parser.OFPMatch(in_port=in_port, ipv4_dst=ipv4_packet.dst, eth_type=ether_types.ETH_TYPE_IP)
                        self.add_flow(datapath=datapath, priority=PRIO_DROP, match=match, actions=[])
                        logger.debug(f"Added rule: match={match}, actions={[]} on router;")
                        self.same_network_ip_drop_rules[in_port].append(ipv4_packet.dst)
                    else:
                        logger.critical(f"Existing IP drop rule did not match: in_port={in_port} dst_ip={ipv4_packet.dst}")
                elif self.ip_to_mac.get(ipv4_packet.dst):
                    logger.info(f"For IP-Address={ipv4_packet.dst}, found dst_mac={self.ip_to_mac.get(ipv4_packet.dst)}")
                    outs.append(self.forward_ipv4_packet(datapath=datapath, data=msg.data, in_port=in_port, eth_dst=self.ip_to_mac[ipv4_packet.dst]))
                else:
                    target_network = ip_network((ipv4_packet.dst, netmask), strict=False).network_address
                    port = network_to_port.get(target_network)
                    if port:
                        buffered = {"datapath": datapath, "data": deepcopy(msg.data), "in_port": in_port}
                        self.buffered_msgs[ipv4_packet.dst].append(buffered)
                        logger.info(f"MAC for IP={ipv4_packet.dst} not found. Buffer msg...")
                        logger.debug(f"put in buffer: {pformat(buffered)}")
                        outs.append(self.construct_arp_request(port=port,
                                                               dst_ip=ipv4_packet.dst,
                                                               datapath=datapath,
                                                               parser=parser,
                                                               ofproto=ofproto))
                    else:
                        logger.error(f"Target network unknown: {ipv4_packet.dst} from network {target_network}")
                        send_destination_unreachable(pkt=pkt, eth_packet=eth_packet, ipv4_packet=ipv4_packet,
                                                          datapath=datapath, parser=parser, in_port=in_port,
                                                          ofproto=ofproto, code=0)

        for out in outs:
            logger.debug(f"result={datapath.send_msg(out)}")
>>>>>>> Stashed changes
