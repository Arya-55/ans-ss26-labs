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
from logging import getLogger
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from pprint import pprint


logger = getLogger(__name__)

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.packets_received = 0

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

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.packets_received += 1
        msg = ev.msg
        datapath = msg.datapath

        if datapath.id == 3:
            # handle router (s3) request
            self.handle_router_request(ev)
            return

        # handle switch requests

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        logger.info("Switch Packets:")
        for p in pkt.protocols:
            logger.info(f"\t- {p}")

        eth = pkt.get_protocol(ethernet.ethernet)
        logger.info(f"seq={self.packets_received}: dpid={datapath.id}: in_port={in_port}, eth_src={eth.src}, eth_dst={eth.dst};")

        self.add_flow(datapath=datapath, priority=1,
                      match=ofproto_v1_3_parser.OFPMatch(eth_dst=eth.src),
                      actions=[ofproto_v1_3_parser.OFPActionOutput(port=in_port)])
        logger.info(f"Added rule: match(eth_dst={eth.src}), action(port={in_port}) on dpid={datapath.id};")
        out = ofproto_v1_3_parser.OFPPacketOut(datapath=datapath,
                                               buffer_id=msg.buffer_id,
                                               in_port=in_port,
                                               actions=[ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_FLOOD)],
                                               data=msg.data)
        datapath.send_msg(out)
        logger.info(f"Instruction to dpid={datapath.id}: broadcast")

    def handle_router_request(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        logger.info(f"Packet comes from router and was received on port {in_port}! Protocols:")
        for p in pkt.protocols:
            logger.info(f"\t- {p}")
        
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