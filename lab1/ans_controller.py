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
from copy import deepcopy
from ipaddress import ip_network
from logging import getLogger, StreamHandler, Formatter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, arp, tcp, udp
from ryu.lib.packet.in_proto import IPPROTO_ICMP
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from pprint import pprint, pformat


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


PRIO_FORWARD = 2
PRIO_REPLY = 3
PRIO_DROP = 4


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
        self.netmask = "255.255.255.0"
        self.network_to_port = {ip_network((ip, self.netmask), strict=False).network_address: port for port, ip in self.port_to_own_ip.items()}
        self.mac_to_port = defaultdict(dict)
        self.ip_to_mac = {}
        self.buffered_msgs = defaultdict(list)
        self.same_network_arp_drop_rules = defaultdict(list)
        self.same_network_ip_drop_rules = defaultdict(list)

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
    def packet_out_to_port(*, data, datapath, parser, in_port, port, ofproto):
        return parser.OFPPacketOut(datapath=datapath,
                                   in_port=in_port,
                                   buffer_id=ofproto.OFP_NO_BUFFER,
                                   actions=[parser.OFPActionOutput(port)],
                                   data=data)

    def reply_packet_to_in_port(self, *, in_port, ofproto, **kwargs):
        return self.packet_out_to_port(port=in_port, in_port=ofproto.OFPP_CONTROLLER, ofproto=ofproto,  **kwargs)

    def flood_packet_out(self, *, ofproto, **kwargs):
        return self.packet_out_to_port(port=ofproto.OFPP_FLOOD, ofproto=ofproto, **kwargs)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        num_minus = 20
        print(num_minus * "-" + "_packet_in_handler start" + num_minus * "-")
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

            switch_logger.info("Switch Packets:")
            for p in pkt.protocols:
                switch_logger.info(f"\t- {p}")

            eth = pkt.get_protocol(ethernet.ethernet)
            switch_logger.info(f"seq={self.packet_counter}: dpid={datapath.id}: in_port={in_port}, eth_src={eth.src}, eth_dst={eth.dst};")

            if eth.src not in self.mac_to_port[datapath.id]:
                self.mac_to_port[datapath.id][eth.src] = in_port
                switch_logger.info(f"New MAC for dpid={datapath.id}: {eth.src}")
            if self.mac_to_port.get(datapath.id, {}).get(eth.dst):
                match = parser.OFPMatch(eth_dst=eth.dst, in_port=in_port)
                actions = [parser.OFPActionOutput(port=self.mac_to_port[datapath.id][eth.dst])]
                self.add_flow(datapath=datapath, priority=PRIO_FORWARD, match=match, actions=actions)
                switch_logger.info(f"Added rule: match={match}, actions={actions} on dpid={datapath.id};")
                out = self.packet_out_to_port(data=msg.data, datapath=datapath, parser=parser, in_port=in_port, port=self.mac_to_port[datapath.id][eth.dst], ofproto=ofproto)
            else:
                out = self.flood_packet_out(data=msg.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto)
            datapath.send_msg(out)
            switch_logger.info(f"Instruction to dpid={datapath.id}: broadcast")
        print(num_minus * "-" + "_packet_in_handler end" + num_minus * "-")

    def forward_ipv4_packet(self, datapath, data, in_port, eth_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(data)
        logger.debug(f"Function forward_ipv4_packet(): Protocols:")
        for p in pkt.protocols:
            logger.debug(f"\t- {p}")
        eth_packet = pkt.get_protocol(ethernet.ethernet)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_packet.dst)
        dst_network = ip_network((ipv4_packet.dst, self.netmask), strict=False)
        out_port = self.network_to_port[dst_network.network_address]
        actions = [parser.OFPActionSetField(eth_src=self.port_to_own_mac[out_port]),
                   parser.OFPActionSetField(eth_dst=eth_dst),
                   parser.OFPActionDecNwTtl(),
                   parser.OFPActionOutput(out_port)]
        self.add_flow(datapath=datapath, priority=PRIO_FORWARD, match=match, actions=actions)
        logger.debug(f"Added rule: match={match}, actions={actions} on router;")

        eth_packet.src = self.port_to_own_mac[out_port]
        eth_packet.dst = eth_dst
        eth_packet.ethertype = ether_types.ETH_TYPE_IP
        logger.debug(f"prepared fwd: {ipv4_packet}, eth_dst={eth_dst}, eth_packet.src={eth_packet.src}, eth_packet={eth_packet}, dpid={datapath.id}, in_port={in_port}")
        pkt.serialize()

        logger.info(f"forward to ip={ipv4_packet.dst}, mac={eth_dst}")
        return self.packet_out_to_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, port=out_port, ofproto=ofproto)

    def construct_arp_request(self, port, dst_ip, datapath, parser, ofproto):
        eth_packet = ethernet.ethernet(src=self.port_to_own_mac[port], ethertype=ether_types.ETH_TYPE_ARP)
        arp_packet = arp.arp(opcode=arp.ARP_REQUEST, src_mac=self.port_to_own_mac[port], src_ip=self.port_to_own_ip[port], dst_ip=dst_ip)
        pkt = packet.Packet()
        pkt.add_protocol(eth_packet)
        pkt.add_protocol(arp_packet)
        pkt.serialize()
        logger.info(f"arp request for {dst_ip}")
        return self.packet_out_to_port(data=pkt.data, datapath=datapath, parser=parser, in_port=ofproto.OFPP_CONTROLLER, port=port, ofproto=ofproto)

    def handle_router_request(self, ev):
        num_minus = 20
        print(num_minus * "-" + "handle_router_request start" + num_minus * "-")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)

        logger.debug(f"Packet comes from router and was received on port {in_port}! Protocols:")
        for p in pkt.protocols:
            logger.debug(f"\t- {p}")

        eth_packet = pkt.get_protocol(ethernet.ethernet)
        ipv4_packet = pkt.get_protocol(ipv4.ipv4)
        #icmp_packet = pkt.get_protocol(icmp.icmp)
        arp_packet = pkt.get_protocol(arp.arp)
        #tcp_packet = pkt.get_protocol(tcp.tcp)
        #udp_packet = pkt.get_protocol(udp.udp)

        outs = []
        """if udp_packet or tcp_packet:
            # do udp/tcp stuff
            # no connection between ser and ext, otherwise ok
            pass

        if icmp_packet:
            # do icmp stuff
            # internal all allowed (concrete Ip-adresses)
            # gateway pings only to own (subnet) gateway (wenn subnetzte unterschiedlich, dann droppen, sonst icmp reply nach source)
            # none to external
            # none from external
            pass"""

        if arp_packet:
            # do arp stuff
            # answer to in-port with MAC of in-port-gateway (arp reply)
            if arp_packet.dst_ip != self.port_to_own_ip[in_port]:
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
                eth_packet.src, eth_packet.dst = self.port_to_own_mac[in_port], eth_packet.src
                arp_packet.src_mac, arp_packet.dst_mac = self.port_to_own_mac[in_port], arp_packet.src_mac
                arp_packet.src_ip, arp_packet.dst_ip = self.port_to_own_ip[in_port], arp_packet.src_ip
                arp_packet.opcode = 2
                pkt = packet.Packet()
                pkt.add_protocol(eth_packet)
                pkt.add_protocol(arp_packet)
                pkt.serialize()
                outs.append(self.reply_packet_to_in_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto))
                logger.info(f"Instruction: send arp reply")

        if ipv4_packet:
            # do ip stuff
            # prefix matching, next hop (Ethernet-Header Rewriting: MAC-adresse der Source muss MAC adresse des input-ports sein (siehe actions))
            logger.debug(f"ipv4_packet: {ipv4_packet.src} -> {ipv4_packet.dst}; eth_packet: {eth_packet.src} -> {eth_packet.dst};")
            logger.debug(f"self.ip_to_mac={self.ip_to_mac}")
            if eth_packet.src != self.ip_to_mac.get(ipv4_packet.src):
                logger.info(f"Found new IP-MAC pair: {ipv4_packet.src} -> {eth_packet.src}")
                self.ip_to_mac[ipv4_packet.src] = eth_packet.src
            if ipv4_packet.dst in self.port_to_own_ip.values():
                if ipv4_packet.proto == IPPROTO_ICMP:
                    if ipv4_packet.dst != self.port_to_own_ip[in_port]:
                        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_packet.dst)
                        # or maybe OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipv4_packet.dst, ip_proto=IPPROTO_ICMP)
                        actions = []
                        self.add_flow(datapath=datapath, priority=PRIO_DROP, match=match, actions=actions)
                        logger.info(f"pinged wrong Gateway: src={ipv4_packet.src}; dst={ipv4_packet.dst};")
                        logger.debug(f"Added drop rule: match={match}; actions={actions};")
                    else:
                        icmp_packet = pkt.get_protocol(icmp.icmp)
                        logger.info(f"ping Gateway: src={ipv4_packet.src}; dst={ipv4_packet.dst};")
                        eth_packet.src, eth_packet.dst = self.port_to_own_mac[in_port], eth_packet.src
                        ipv4_packet.src, ipv4_packet.dst = self.port_to_own_ip[in_port], ipv4_packet.src
                        icmp_packet.type = icmp.ICMP_ECHO_REPLY
                        pkt = packet.Packet()
                        pkt.add_protocol(eth_packet)
                        pkt.add_protocol(ipv4_packet)
                        pkt.add_protocol(icmp_packet)
                        pkt.serialize()
                        outs.append(self.reply_packet_to_in_port(data=pkt.data, datapath=datapath, parser=parser, in_port=in_port, ofproto=ofproto))
                        logger.info(f"Instruction: send icmp echo reply")
                else:
                    logger.error(f"unknown IP-Protocol: {ipv4_packet.proto}")

            elif (ip_network((ipv4_packet.src, self.netmask), strict=False) == ip_network((ipv4_packet.dst, self.netmask), strict=False) and
                    ipv4_packet.dst != self.port_to_own_ip[in_port]):
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
                buffered = {"datapath": datapath, "data": deepcopy(msg.data), "in_port": in_port}
                self.buffered_msgs[ipv4_packet.dst].append(buffered)
                logger.info(f"MAC for IP={ipv4_packet.dst} not found. Buffer msg...")
                logger.debug(f"put in buffer: {pformat(buffered)}")
                outs.append(self.construct_arp_request(port=self.network_to_port[ip_network((ipv4_packet.dst, self.netmask), strict=False).network_address],
                                                       dst_ip=ipv4_packet.dst,
                                                       datapath=datapath,
                                                       parser=parser,
                                                       ofproto=ofproto))

        for out in outs:
            logger.debug(f"result={datapath.send_msg(out)}: {out}")
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