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
from logging import getLogger
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, arp, tcp, udp
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from pprint import pprint


logger = getLogger(__name__)


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
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }

        self.mac_to_port = defaultdict(dict)

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

        # drop IPv6 for now
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, 3, match, actions)

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
    def packet_out_to_port(msg, datapath, parser, in_port, port):
        return parser.OFPPacketOut(datapath=datapath,
                                   buffer_id=msg.buffer_id,
                                   in_port=in_port,
                                   actions=[parser.OFPActionOutput(port)],
                                   data=msg.data)

    def reply_packet_to_in_port(self, *, in_port, **kwargs):
        return self.packet_out_to_port(port=in_port, **kwargs)

    def flood_packet_out(self, *, ofproto, **kwargs):
        return self.packet_out_to_port(port=ofproto.OFPP_FLOOD, **kwargs)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        num_minus = 10
        print(num_minus * "-" + "_packet_in_handler start" + num_minus * "-")
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
            # handle switch requests
            in_port = msg.match["in_port"]
            pkt = packet.Packet(msg.data)

            logger.info("Switch Packets:")
            for p in pkt.protocols:
                logger.info(f"\t- {p}")

            eth = pkt.get_protocol(ethernet.ethernet)
            logger.info(f"seq={self.packet_counter}: dpid={datapath.id}: in_port={in_port}, eth_src={eth.src}, eth_dst={eth.dst};")

            if self.mac_to_port.get(datapath.id, {}).get(eth.dst):
                logger.critical(f"Existing rule did not match: match(eth_dst={eth.src}), action(port={in_port}) on dpid={datapath.id};")
                out = self.packet_out_to_port(msg, datapath, parser, in_port, port=self.mac_to_port[datapath.id][eth.dst])
            else:
                self.mac_to_port[datapath.id][eth.src] = in_port
                self.add_flow(datapath=datapath, priority=2,
                              match=parser.OFPMatch(eth_dst=eth.src),
                              actions=[parser.OFPActionOutput(port=in_port)])
                logger.info(f"Added rule: match(eth_dst={eth.src}), action(port={in_port}) on dpid={datapath.id};")
                out = self.flood_packet_out(msg=msg, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)
            datapath.send_msg(out)
            logger.info(f"Instruction to dpid={datapath.id}: broadcast")
        print(num_minus * "-" + "_packet_in_handler end" + num_minus * "-")

    def handle_router_request(self, ev):
        num_minus = 10
        print(num_minus * "-" + "handle_router_request start" + num_minus * "-")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        logger.info(f"Packet comes from router and was received on port {in_port}! Protocols:")
        for p in pkt.protocols:
            logger.info(f"\t- {p}")

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        icmp_packet = pkt.get_protocol(icmp.icmp)
        arp_packet = pkt.get_protocol(arp.arp)
        tcp_packet = pkt.get_protocol(tcp.tcp)
        udp_packet = pkt.get_protocol(udp.udp)

        if udp_packet or tcp_packet:
            # do udp/tcp stuff
            # no connection between ser and ext, otherwise ok
            pass

        if icmp_packet:
            # do icmp stuff
            # internal all allowed (concrete Ip-adresses)
            # gateway pings only to own (subnet) gateway (wenn subnetzte unterschiedlich, dann droppen, sonst icmp reply nach source)
            # none to external
            # none from external
            pass

        if arp_packet:
            # do arp stuff
            # answer to in-port with MAC of in-port-gateway (arp reply)
            # rule: send arp reply with gateway mac
            match = parser.OFPMatch(in_port=in_port, arp_sha=arp_packet.src_mac, arp_spa=arp_packet.src_ip, arp_op=2)
            actions = [parser.OFPActionSetfield(opcode=2,
                                                src_mac=self.port_to_own_mac[in_port], dst_mac=arp_packet.src_mac,
                                                src_ip=self.port_to_own_ip[in_port], dst_ip=arp_packet.src_ip),
                       parser.OFPActionOutput(port=in_port)]
            self.add_flow(datapath=datapath, priority=2, match=match, actions=actions)
            logger.info(f"Added rule: match(in_port={in_port}, arp_sha={arp_packet.src_mac}, arp_spa={arp_packet.src_ip}, arp_op=2),"
                        f"action(port={in_port}) on router;")

            # send arp reply manually the first time
            eth_packet.src, eth_packet.dst = self.port_to_own_mac[in_port], eth_packet.src
            arp_packet.src_mac, arp_packet.dst_mac = self.port_to_own_mac[in_port], arp_packet.src_mac
            arp_packet.src_ip, arp_packet.dst_ip = self.port_to_own_ip[in_port], arp_packet.src_ip
            pkt = packet.Packet()
            pkt.add_protocol(eth_packet)
            pkt.add_protocol(arp_packet)
            pkt.serialize()
            out = self.reply_packet_to_in_port(data=msg.data, datapath=datapath, parser=parser, in_port=in_port)
            logger.info(f"Instruction to router: send arp reply")

        if ipv4_packet:
            # do ip stuff
            # prefix matching, next hop (Ethernet-Header Rewriting: MAC-adresse der Source muss MAC adresse des input-ports sein (siehe actions))
            pass

        datapath.send_msg(out)
        # do ethernet stuff?

        # ping packets have ipv6 and icmpv6 -> Ping uses icmp
        # iperf generates arp packages

        # must answer ARP-Packets as hosts will ARP for IP Gateways
        # "10.0.1.1"    ? => "00:00:00:00:01:01"
        # "10.0.2.1"    ? => "00:00:00:00:01:02",
        # "192.168.1.1" ? => "00:00:00:00:01:03"

        # router needs to rewrite ethernet headers when forwarding its packets (correkt?)

        # ext may not ping internal hosts => drop ICMP packets from ext
            # what about from internal hosts to extern, according to the given result they should also not be able to ping ext
        # no TCP/UDP allowed between ext and ser => drop TCP/UDP packets with respective src/dst-pairs
        # hosts may only ping their own gateway => drop ICMP packages if src-ip != dst-ip
        print(num_minus * "-" + "handle_router_request end" + num_minus * "-")