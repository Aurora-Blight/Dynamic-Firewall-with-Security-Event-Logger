"""
firewall.py - Ryu controller: SDN dynamic firewall with security event logging.

Run:   ryu-manager firewall.py

How it works
  * Table-miss sends unknown packets to the controller (packet-in).
  * Non-TCP traffic (ARP, ICMP, ...) is handled by a plain L2 learning switch.
  * Every NEW TCP connection (exact 5-tuple) causes a packet-in.  The controller
    classifies it by source / destination / port (policy.py) and installs an
    allow or deny (drop) flow.
  * Attempts to the restricted port are counted per host; more than MAX_ATTEMPTS
    within WINDOW_SECS installs a high-priority drop rule for that host (BLOCK).
    After BLOCK_SECS the rule is removed again (UNBLOCK).
  * Every event is queued and sent as one JSON line to logger_server.py over TCP.
"""
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

import policy as P

PRIO_TABLE_MISS = 0
PRIO_L2 = 5          # ARP / ICMP / other non-TCP learning-switch flows
PRIO_TCP = 10        # exact per-connection allow / deny flows
PRIO_BLOCK = 100     # per-host block rule (overrides everything)

TCP_FLOW_IDLE = 10   # seconds
DENY_FLOW_IDLE = 5
L2_FLOW_IDLE = 30

IP_PROTO_TCP = 6


class DynamicFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.tracker = P.AttemptTracker()
        self.blocked = {}                 # ip -> time.time() when blocked
        self.event_queue = hub.Queue()
        hub.spawn(self._event_sender)
        hub.spawn(self._recovery_loop)

    # ------------------------------------------------------------ switch up
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.datapaths[dp.id] = dp
        # table-miss: send everything unknown to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_TABLE_MISS, match, actions)
        self.logger.info("switch %s connected", dp.id)

    # ------------------------------------------------------------ packet-in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        t0 = time.perf_counter()          # start of controller-side processing
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)

        ip = pkt.get_protocol(ipv4.ipv4)
        tp = pkt.get_protocol(tcp.tcp)

        if ip is not None and ip.proto == IP_PROTO_TCP:
            if tp is None:                # e.g. fragment - cannot classify, drop
                return
            self._handle_tcp(dp, msg, in_port, out_port, ip, tp, t0)
        else:
            self._handle_other(dp, msg, in_port, out_port, eth, ip)

    # ------------------------------------------------------- non-TCP traffic
    def _handle_other(self, dp, msg, in_port, out_port, eth, ip):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        if out_port != ofp.OFPP_FLOOD:
            fields = dict(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                          eth_type=eth.ethertype)
            if ip is not None:
                fields["ip_proto"] = ip.proto
            self._add_flow(dp, PRIO_L2, parser.OFPMatch(**fields),
                           [parser.OFPActionOutput(out_port)], idle=L2_FLOW_IDLE)
        self._packet_out(dp, msg, in_port, out_port)

    # ------------------------------------------------------------ TCP traffic
    def _handle_tcp(self, dp, msg, in_port, out_port, ip, tp, t0):
        ofp = dp.ofproto
        src, dst = ip.src, ip.dst
        sport, dport = tp.src_port, tp.dst_port
        is_syn = bool(tp.bits & tcp.TCP_SYN) and not (tp.bits & tcp.TCP_ACK)

        if src in self.blocked:           # packet-in raced with the block rule
            return

        # server -> client packets of an allowed connection
        if P.is_return_traffic(src, sport, dport):
            if out_port != ofp.OFPP_FLOOD:
                self._install_tcp_flow(dp, in_port, out_port, src, dst, sport, dport)
            self._packet_out(dp, msg, in_port, out_port)
            return

        action, reason = P.classify(src, dst, dport)

        if action == "allow":
            if dport == P.RESTRICTED_PORT and is_syn:     # count connection attempts only
                if self.tracker.record(src):
                    self._block(src, dst, dport, t0)
                    return
            if out_port != ofp.OFPP_FLOOD:
                self._install_tcp_flow(dp, in_port, out_port, src, dst, sport, dport)
                self._install_tcp_flow(dp, out_port, in_port, dst, src, dport, sport)
            self._packet_out(dp, msg, in_port, out_port)
            if is_syn:
                self._log("ALLOW", src, dst, dport, reason, t0)
        else:
            self._install_tcp_flow(dp, in_port, None, src, dst, sport, dport,
                                   idle=DENY_FLOW_IDLE)      # drop flow
            if is_syn:
                self._log("DENY", src, dst, dport, reason, t0)

    # ----------------------------------------------------------- block / unblock
    def _block(self, src, dst, dport, t0):
        self.blocked[src] = time.time()
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            # remove any existing flows to/from the host, then drop everything from it
            self._delete_flows(dp, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                   ipv4_src=src))
            self._delete_flows(dp, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                   ipv4_dst=src))
            self._add_flow(dp, PRIO_BLOCK,
                           parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src),
                           [])
        reason = ">%d attempts to port %d within %ds -> blocked for %ds" % (
            P.MAX_ATTEMPTS, P.RESTRICTED_PORT, P.WINDOW_SECS, P.BLOCK_SECS)
        self._log("BLOCK", src, dst, dport, reason, t0)

    def _unblock(self, src):
        self.blocked.pop(src, None)
        self.tracker.reset(src)
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            self._delete_flows(dp, parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                   ipv4_src=src),
                               priority=PRIO_BLOCK, strict=True)
        self._log("UNBLOCK", src, None, None, "block period of %ds expired" % P.BLOCK_SECS)

    def _recovery_loop(self):
        while True:
            hub.sleep(0.5)
            now = time.time()
            for ip, since in list(self.blocked.items()):
                if now - since >= P.BLOCK_SECS:
                    self._unblock(ip)

    # ------------------------------------------------------------ OpenFlow helpers
    def _install_tcp_flow(self, dp, in_port, out_port, src, dst, sport, dport,
                          idle=TCP_FLOW_IDLE):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=IP_PROTO_TCP, ipv4_src=src, ipv4_dst=dst,
                                tcp_src=sport, tcp_dst=dport)
        actions = [] if out_port is None else [parser.OFPActionOutput(out_port)]
        self._add_flow(dp, PRIO_TCP, match, actions, idle=idle)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = []
        if actions:
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      hard_timeout=hard))

    def _delete_flows(self, dp, match, priority=0, strict=False):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        cmd = ofp.OFPFC_DELETE_STRICT if strict else ofp.OFPFC_DELETE
        dp.send_msg(parser.OFPFlowMod(datapath=dp, command=cmd, priority=priority,
                                      out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                      match=match))

    def _packet_out(self, dp, msg, in_port, out_port):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port,
                                        actions=[parser.OFPActionOutput(out_port)],
                                        data=data))

    # ---------------------------------------------------------------- logging
    def _log(self, event, src, dst, port, reason, t0=None):
        evt = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ts": round(time.time(), 6),
            "event": event,
            "src": src,
            "dst": dst,
            "port": port,
            "reason": reason,
        }
        if t0 is not None:
            # controller-side processing time from packet-in to flow-mod being queued
            evt["response_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        self.logger.info("%s %s -> %s:%s (%s)", event, src, dst, port, reason)
        self.event_queue.put(evt)

    def _event_sender(self):
        """Ships queued events to the logging server (kept off the packet-in path)."""
        sock = None
        while True:
            evt = self.event_queue.get()
            line = (json.dumps(evt) + "\n").encode()
            for _ in range(2):
                try:
                    if sock is None:
                        sock = socket.create_connection(P.LOGGER_ADDR, timeout=2)
                    sock.sendall(line)
                    break
                except OSError:
                    if sock is not None:
                        sock.close()
                    sock = None
            else:
                self.logger.warning("logger unreachable, event not delivered: %s", evt)
