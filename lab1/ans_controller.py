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
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, tcp, udp
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from pprint import pprint


logger = getLogger(__name__)
PRIO_FW = 3
PRIO_STD = 2


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

    def flood_packet_out(self, *, ofproto, **kwargs):
        return self.packet_out_to_port(port=ofproto.OFPP_FLOOD, **kwargs)

    def matches_subnet(self, ip_addr, in_port):
        gateway = self.port_to_own_ip[in_port]
        return ip_addr.startswith(gateway[:gateway.rfind(".")])

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
                self.add_flow(datapath=datapath, priority=PRIO_STD,
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

        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            logger.info(f"\tGot an ARP packet: {arp_pkt}")
            ip_src = arp_pkt.src_ip

            #TODO: Router has to stop ARP broadcasts
            #TODO: Drop Package that request/reply to 10.0.1.3 and 10.0.1.2 (Those have to be answered by h1 or h2 respectively)
            #TODO: Answer Packages for any other ip address with the MAC-Address of the port at which the request arrived (send back towards source ip)

        if ip:
            logger.info(f"\tGot an IP packet: {ip}")
            ip_src = ip.src
            ip_dst = ip.dst
            
            if in_port != 1:
                # IP packet comes from one of the servers
                if self.matches_subnet(ip_dst, 2) or self.matches_subnet(ip_dst, 3):
                    # and tries to go to the other server 
                    if ip.proto in [1, 6, 17]:
                        # which is not allowed for ICMP (ip_proto = 1) and TCP/UDP (ip_proto = 6/17)
                        self.add_flow(datapath=datapath, 
                                      priority=PRIO_FW, 
                                      match=parser.OFPMatch(eth_type=0x0800, ip_proto=ip.proto, ipv4_src = ip_src, ipv4_dst = ip_dst), 
                                      actions=[])   # no actions == drop
                        logger.info(f"Added Firewall-Rule: No IP-Traffic of type TCP/UDP or ICMP between {ip_src} and {ip_dst} allowed.")
                        # no further processing
                    else:
                        #TODO: Other protocols are not prohibited in the excercise => forwarding rule needed?
                        pass
                else:
                    # IP Packet wants to go to subnet 10.0.1.1/24
                    #TODO: Add flow-rule to forward packet, incl. decrementing TTL and rewriting MAC-Adresses in ethernet header  
                    pass
                #TODO: Probably don't need both else-cases and can just add a forwarding flow rule here for all other cases fromone of the servers
            else:
                # IP packet comes from the subnet 10.0.1.1/24
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                
                if icmp_pkt:
                    # It's an ICMP packet
                    if self.matches_subnet(ip_dst, 3):
                        # and tries to go to the external server which is not allowed:
                        self.add_flow(datapath=datapath, 
                                      priority=PRIO_FW, 
                                      match=parser.OFPMatch(eth_type=0x0800, ip_proto=ip.proto, ipv4_src = ip_src, ipv4_dst = ip_dst), 
                                      actions=[])   # no actions == drop
                        logger.info(f"Added Firewall-Rule: No ICMP-Traffic between {ip_src} and {ip_dst} allowed.")
                        # no further processing
                    else:
                        # ICMP Packets to other parts of the network are allowed
                        #TODO: handle this (does this need different handling than TCP/UDP? Can ICMP be addressed to the router itself?)
                        pass
                else:
                    # Other IP-Proto
                    #TODO: Add flow-rule to forward packet, incl. decrementing TTL and rewriting MAC-Adresses in ethernet header
                    pass
                # TODO: Might need the Else-Stuff, if ICMP has to be handled differently than the other rules
                        
        print(num_minus * "-" + "handle_router_request end" + num_minus * "-")