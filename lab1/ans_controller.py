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
from collections import defaultdict
from ipaddress import ip_address, ip_network, IPv4Network
from logging import getLogger
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, in_proto, icmp, arp #, tcp, udp
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from pprint import pprint


logger = getLogger(__name__)
PRIO_FIREWALL = 5
PRIO_STANDARD = 2
PRIO_CATCHALL = 0

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.packet_counter = 0

        # Router port MACs assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }

        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",          # internal host gateway (s1 subnet)
            2: "10.0.2.1",          # internal server gateway (ser)
            3: "192.168.1.1"        # external server gateway (ext)
        }

        self.netmask = 24
        self.network_to_port = {ip_network((ip, self.netmask), strict=False).network_address: port for port, ip in self.port_to_own_ip.items()}
        self.mac_to_port = defaultdict(dict)
        self.ip_to_mac = {}
        self.buffered_ipv4_packets = defaultdict(list)

        self.firewall = [
            {   # no ICMP from ext to any intern (only own gateway)
                "proto": in_proto.IPPROTO_ICMP,
                "src": ip_network("192.168.1.0/24"),
                "dst": ip_network("10.0.0.0/16")
            },
            {
                # no ICMP from intern to extern
                "proto": in_proto.IPPROTO_ICMP,
                "src": ip_network("10.0.0.0/16"),
                "dst": ip_network("192.168.1.0/24")
            },
            {
                # no TCP from ser to ext
                "proto": in_proto.IPPROTO_TCP,
                "src": ip_network("10.0.2.0/24"),
                "dst": ip_network("192.168.1.0/24")
            },
            {
                # no TCP from ext to ser
                "proto": in_proto.IPPROTO_TCP,
                "src": ip_network("192.168.1.0/24"),
                "dst": ip_network("10.0.2.0/24")
            },
            {
                # no UDP from ser to ext
                "proto": in_proto.IPPROTO_UDP,
                "src": ip_network("10.0.2.0/24"),
                "dst": ip_network("192.168.1.0/24")
            },
            {
                # no UDP from ext to ser
                "proto": in_proto.IPPROTO_UDP,
                "src": ip_network("192.168.1.0/24"),
                "dst": ip_network("10.0.2.0/24")
            }
        ]


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, PRIO_CATCHALL, match, actions)

        # drop IPv6 for now
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, PRIO_FIREWALL, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # @staticmethod
    # def packet_out_to_port(data, datapath, parser, in_port, port, ofproto):
    #     return parser.OFPPacketOut(datapath=datapath,
    #                                in_port=in_port,
    #                                buffer_id=ofproto.OFP_NO_BUFFER,
    #                                actions=[parser.OFPActionOutput(port)],
    #                                data=data)

    # def reply_packet_to_in_port(self, *, in_port, ofproto, **kwargs):
    #     return self.packet_out_to_port(port=in_port, in_port=ofproto.OFPP_CONTROLLER, ofproto=ofproto,  **kwargs)

    # def flood_packet_out(self, *, ofproto, **kwargs):
    #     return self.packet_out_to_port(port=ofproto.OFPP_FLOOD, ofproto=ofproto, **kwargs)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #num_minus = 10
        #print(num_minus * "-" + "_packet_in_handler start" + num_minus * "-")
        # print(f"self.mac_to_port={self.mac_to_port}")

        self.packet_counter += 1
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if datapath.id == 3:
            # handle router (s3) request
            self.handle_router_request(ev)

        else:
            num_minus = 10
            print("\n" + num_minus * "-" + "Switch Request start (_packet_in_handler)" + num_minus * "-")
            # handle switch requests
            in_port = msg.match["in_port"]
            pkt = packet.Packet(msg.data)

            #logger.info("Switch Packets:")
            #for p in pkt.protocols:
            #    logger.info(f"\t- {p}")

            eth = pkt.get_protocol(ethernet.ethernet)
            logger.info(f"seq={self.packet_counter}: dpid={datapath.id}: in_port={in_port}, eth_src={eth.src}, eth_dst={eth.dst};")

            if self.mac_to_port.get(datapath.id, {}).get(eth.dst):
                logger.critical(f"Existing rule did not match: match(eth_dst={eth.src}), action(port={in_port}) on dpid={datapath.id};")
                out = self.packet_out_to_port(msg.data, datapath, parser, in_port, port=self.mac_to_port[datapath.id][eth.dst], ofproto=ofproto)
            else:
                self.mac_to_port[datapath.id][eth.src] = in_port
                self.add_flow(datapath=datapath, priority=PRIO_STANDARD,
                              match=parser.OFPMatch(eth_dst=eth.src),
                              actions=[parser.OFPActionOutput(port=in_port)])
                logger.info(f"Added rule: match(eth_dst={eth.src}), action(port={in_port}) on dpid={datapath.id};")
                out = self.flood_packet_out(data=msg.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)
            datapath.send_msg(out)
            logger.info(f"Instruction to dpid={datapath.id}: broadcast")
            #print(num_minus * "-" + "Switch Request end (_packet_in_handler)" + num_minus * "-")


    @staticmethod
    def packet_out_to_port(data, datapath, parser, in_port, port, ofproto):
        return parser.OFPPacketOut(datapath=datapath,
                                   in_port=in_port,
                                   buffer_id=ofproto.OFP_NO_BUFFER,
                                   actions=[parser.OFPActionOutput(port)],
                                   data=data)


    def reply_packet_to_in_port(self, *, in_port, ofproto, **kwargs):
        return self.packet_out_to_port(port=in_port, in_port=ofproto.OFPP_CONTROLLER, ofproto=ofproto,  **kwargs)


    def flood_packet_out(self, *, ofproto, **kwargs):
        return self.packet_out_to_port(port=ofproto.OFPP_FLOOD, ofproto=ofproto, **kwargs)


    def forward_ipv4_packet(self, ipv4_packet, eth_dst, eth_packet, datapath, parser, in_port, ofproto):
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=(ipv4_packet.dst, 24))
        dst_network = ip_network((ipv4_packet.dst, self.netmask), strict=False)
        out_port = self.network_to_port[dst_network.network_address]
        actions = [parser.OFPActionSetField(eth_src=self.port_to_own_mac[out_port]),
                   parser.OFPActionSetField(eth_dst=eth_dst),
                   parser.OFPActionOutput(out_port)]
        self.add_flow(datapath=datapath, priority=PRIO_STANDARD, match=match, actions=actions)
        logger.info(f"Added rule: match={match}, action={actions} on router;")

        eth_packet.src = self.network_to_port[dst_network.network_address]
        eth_packet.dst = eth_dst
        pkt = packet.Packet()
        pkt.add_protocol(eth_packet)
        pkt.add_protocol(ipv4_packet)
        pkt.serialize()

        logger.info(f"Instruction to router: forward to ip={ipv4_packet.dst}, mac={eth_dst}")
        return self.packet_out_to_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, port=out_port, ofproto=ofproto)


    def construct_arp_request(self, port, dst_ip, datapath, parser, ofproto):
        eth_packet = ethernet.ethernet(src=self.port_to_own_mac[port], ethertype=ether_types.ETH_TYPE_ARP)
        arp_packet = arp.arp(opcode=arp.ARP_REQUEST, src_mac=self.port_to_own_mac[port], src_ip=self.port_to_own_ip[port], dst_ip=dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth_packet)
        pkt.add_protocol(arp_packet)
        pkt.serialize()
        logger.info(f"Instruction to router: arp request for {dst_ip}")
        return self.packet_out_to_port(data=pkt.data, datapath=datapath, parser=parser, in_port=ofproto.OFPP_CONTROLLER, port=port, ofproto=ofproto)


    def check_for_firewall_entry(self, ipv4_packet):
        logger.info(f"Checking IPv4 packet against firewall:\n{ipv4_packet}")
        for entry in self.firewall:
            if all(getattr(ipv4_packet, key) == value if isinstance(value, int) else ip_address(getattr(ipv4_packet, key)) 
                   in value for key, value in entry.items()): 
                logger.info(f"Found firewall entry: {entry}") 
                return {"ip_proto": entry["proto"], "ipv4_src": ipv4_packet.src, "ipv4_dst": ipv4_packet.dst} 
            logger.info(f"No matching firewall entry found")
            return None 


    def handle_router_request(self, ev):
        num_minus = 10
        print("\n" + num_minus * "-" + "Router Request start (handle_router_request)" + num_minus * "-")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        #logger.info(f"Packet comes from router and was received on port {in_port}! Protocols:")
        #for p in pkt.protocols:
        #    logger.info(f"\t- {p}")

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        # icmp_packet = pkt.get_protocol(icmp.icmp)
        arp_packet = pkt.get_protocol(arp.arp)
        # tcp_packet = pkt.get_protocol(tcp.tcp)
        # udp_packet = pkt.get_protocol(udp.udp)

        outs = []
        # if udp_packet or tcp_packet:
        #     # do udp/tcp stuff
        #     # no connection between ser and ext, otherwise ok
        #     pass

        # if icmp_packet:
        #     # do icmp stuff
        #     # internal all allowed (concrete Ip-adresses)
        #     # gateway pings only to own (subnet) gateway (wenn subnetzte unterschiedlich, dann droppen, sonst icmp reply nach source)
        #     # none to external
        #     # none from external
        #     pass

        if arp_packet:
            logger.info("Got ARP packet")
            # do arp stuff
            # answer to in-port with MAC of in-port-gateway (arp reply)
            if arp_packet.opcode == arp.ARP_REPLY:  # process arp reply
                logger.info("Processing ARP REPLY message")
                self.ip_to_mac[arp_packet.src_ip] = arp_packet.src_mac
                if self.buffered_ipv4_packets[arp_packet.src_ip]:
                    buffered_packet = self.buffered_ipv4_packets[arp_packet.src_ip].pop(0)
                    outs.append(self.forward_ipv4_packet(ipv4_packet=buffered_packet,
                                                         eth_dst=arp_packet.src_mac,#
                                                         eth_packet=eth_packet,
                                                         datapath=datapath,
                                                         parser=parser,
                                                         in_port=ofproto.OFPP_CONTROLLER,
                                                         ofproto=ofproto))
            else:  # reply to arp request
                logger.info("Processing ARP REQUEST message")
                match = parser.OFPMatch(in_port=in_port, arp_op=arp.ARP_REQUEST, eth_type=ether_types.ETH_TYPE_ARP)
                actions = [parser.OFPActionSetField(arp_op=arp.ARP_REPLY),
                           parser.OFPActionSetField(eth_src=self.port_to_own_mac[in_port]),
                           parser.OFPActionSetField(eth_dst=arp_packet.src_mac),
                           parser.OFPActionSetField(arp_sha=self.port_to_own_mac[in_port]),
                           parser.OFPActionSetField(arp_tha=arp_packet.src_mac),
                           parser.OFPActionSetField(arp_spa=self.port_to_own_ip[in_port]),
                           parser.OFPActionSetField(arp_tpa=arp_packet.src_ip),
                           parser.OFPActionOutput(port=in_port)]
                # rule: send arp reply with gateway mac
                self.add_flow(datapath=datapath, priority=PRIO_STANDARD, match=match, actions=actions)
                logger.info(f"Added rule: match={match}, action={actions} on router;")

                # send arp reply manually the first time
                eth_packet.src, eth_packet.dst = self.port_to_own_mac[in_port], eth_packet.src
                arp_packet.src_mac, arp_packet.dst_mac = self.port_to_own_mac[in_port], arp_packet.src_mac
                arp_packet.src_ip, arp_packet.dst_ip = self.port_to_own_ip[in_port], arp_packet.src_ip
                arp_packet.opcode = 2
                pkt = packet.Packet()
                pkt.add_protocol(eth_packet)
                pkt.add_protocol(arp_packet)
                pkt.serialize()
                outs.append(self.reply_packet_to_in_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto))
                logger.info(f"Instruction to router: send arp reply")

        if ipv4_packet:
            logger.info("Got IPv4 packet")
            # do ip stuff
            # prefix matching, next hop (Ethernet-Header Rewriting: MAC-adresse der Source muss MAC adresse des input-ports sein (siehe actions))
            firewall_entry = self.check_for_firewall_entry(ipv4_packet)

            if firewall_entry:
                # There is an entry in the firewall-table fitting this packet => add dropping rule
                match = parser.OFPMatch(eth_type=0x0800, **firewall_entry)
                self.add_flow(datapath=datapath, 
                              priority=PRIO_FIREWALL, 
                              match=match, 
                              actions=[])
                logger.info(f"Added firewall rule on router: match={match}, action=[]")
            else:
                # IP forwarding
                if self.ip_to_mac.get(ipv4_packet.dst):
                    logger.info(f"For IP-Address={ipv4_packet.dst}, found dst_mac={self.ip_to_mac.get(ipv4_packet.dst)}")
                    outs.append(self.forward_ipv4_packet(ipv4_packet=ipv4_packet,
                                                         eth_dst=self.ip_to_mac[ipv4_packet.dst],
                                                         eth_packet=eth_packet,
                                                         datapath=datapath,
                                                         parser=parser,
                                                         in_port=in_port,
                                                         ofproto=ofproto))
                else:
                    logger.info(f"For IP-Address={ipv4_packet.dst}, found no dst_mac. Buffering packet and sending ARP REQUEST")
                    self.buffered_ipv4_packets[ipv4_packet.dst].append(ipv4_packet)
                    outs.append(self.construct_arp_request(port=self.network_to_port[ip_network((ipv4_packet.dst, self.netmask), strict=False).network_address],
                                                           dst_ip=ipv4_packet.dst,
                                                           datapath=datapath,
                                                           parser=parser,
                                                           ofproto=ofproto))

        [datapath.send_msg(out) for out in outs]
        #print(num_minus * "-" + "Router Request end (handle_router_request)" + num_minus * "-")