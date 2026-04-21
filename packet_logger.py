#!/usr/bin/env python3
"""
SDN Packet Logger — Ryu Controller Application
Captures and logs packets via OpenFlow packet_in events.
Includes L2 MAC learning so packets are actually forwarded (pingall works).

Requirements:
    pip install ryu

Run:
    ryu-manager sdn_packet_logger.py

Mininet test:
    sudo /path/to/mn --controller=remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13
    mininet> pingall
"""

import csv
import datetime
import threading
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ipv6, tcp, udp, icmp, icmpv6, arp


# ─────────────────────────── ANSI colours ───────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"

PROTO_COLORS = {
    "TCP":    C.BLUE,
    "UDP":    C.GREEN,
    "ICMP":   C.YELLOW,
    "ICMPv6": C.YELLOW,
    "ARP":    C.CYAN,
    "IPv6":   C.CYAN,
    "ETH":    C.GRAY,
}

LOG_FILE        = "packet_log.csv"
BANNER_INTERVAL = 40


# ─────────────────────────── Helpers ────────────────────────────────
def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def proto_badge(name: str) -> str:
    color = PROTO_COLORS.get(name, C.WHITE)
    return f"{color}{C.BOLD}{name:<6}{C.RESET}"


def now_ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def print_banner(stats: dict) -> None:
    w = 90
    print(f"\n{C.BOLD}{C.WHITE}{'─'*w}{C.RESET}")
    print(
        f"{C.BOLD}{C.WHITE}  SDN PACKET LOGGER{C.RESET}"
        f"  {C.DIM}controller OpenFlow 1.3{C.RESET}"
        f"  {C.GRAY}log → {LOG_FILE}{C.RESET}"
    )
    print(
        f"  {C.DIM}packets: {C.WHITE}{stats['total']:<7}{C.RESET}"
        f"  {C.DIM}bytes: {C.WHITE}{fmt_bytes(stats['bytes']):<10}{C.RESET}"
        f"  {C.DIM}flows: {C.WHITE}{stats['flows']:<6}{C.RESET}"
        f"  {C.DIM}switches: {C.WHITE}{stats['switches']}{C.RESET}"
    )
    print(f"{C.BOLD}{C.WHITE}{'─'*w}{C.RESET}")
    print(
        f"  {C.BOLD}{C.WHITE}{'TIME':<13} {'PROTO':<8} {'SRC IP':<18} {'DST IP':<18}"
        f" {'SPORT':<7} {'DPORT':<7} {'LEN':<6} {'SWITCH':<8} FLAGS{C.RESET}"
    )
    print(f"{C.GRAY}{'─'*w}{C.RESET}")


def extract_flags(tcp_pkt) -> str:
    if tcp_pkt is None:
        return ""
    bits = tcp_pkt.bits
    flags = []
    if bits & 0x02: flags.append("SYN")
    if bits & 0x10: flags.append("ACK")
    if bits & 0x01: flags.append("FIN")
    if bits & 0x04: flags.append("RST")
    if bits & 0x08: flags.append("PSH")
    if bits & 0x20: flags.append("URG")
    return "|".join(flags)


# ─────────────────────────── Ryu App ────────────────────────────────
class PacketLogger(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock       = threading.Lock()
        self._row_count  = 0
        self._stats      = defaultdict(int)
        self._flows      = set()
        self._switches   = set()
        self.mac_to_port = {}          # {dpid: {mac: port}}

        self._csv_fh = open(LOG_FILE, "w", newline="", buffering=1)
        self._csv    = csv.writer(self._csv_fh)
        self._csv.writerow([
            "timestamp", "switch_dpid", "in_port",
            "eth_src", "eth_dst", "eth_type",
            "protocol", "src_ip", "dst_ip",
            "src_port", "dst_port", "length",
            "tcp_flags", "ttl", "icmp_type"
        ])
        # print_banner(self._stats)

    # ── Switch handshake ─────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp     = ev.msg.datapath
        ofp    = dp.ofproto
        parser = dp.ofproto_parser
        dpid   = format(dp.id, "016x")

        with self._lock:
            self._switches.add(dpid)
            self._stats["switches"] = len(self._switches)

        self.mac_to_port[dp.id] = {}

        print(f"\n{C.GREEN}[+] Switch connected{C.RESET}  dpid={C.BOLD}{dpid}{C.RESET}")

        # Table-miss: send unmatched packets to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst    = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod     = parser.OFPFlowMod(
            datapath=dp, priority=0, match=match, instructions=inst
        )
        dp.send_msg(mod)

    # ── Packet-in handler ────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        parser  = dp.ofproto_parser
        dpid    = format(dp.id, "016x")
        in_port = msg.match["in_port"]
        data    = msg.data
        pkt     = packet.Packet(data)
        ts      = now_ts()

        # ── Ethernet ──
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        eth_src  = eth_pkt.src
        eth_dst  = eth_pkt.dst
        eth_type = hex(eth_pkt.ethertype)

        # ── Protocol parsing ──
        proto     = "ETH"
        src_ip    = ""
        dst_ip    = ""
        src_port  = ""
        dst_port  = ""
        tcp_flags = ""
        ttl       = ""
        icmp_type = ""

        ip4     = pkt.get_protocol(ipv4.ipv4)
        ip6     = pkt.get_protocol(ipv6.ipv6)
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            proto  = "ARP"
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

        elif ip4:
            src_ip = ip4.src
            dst_ip = ip4.dst
            ttl    = str(ip4.ttl)

            tcp_pkt  = pkt.get_protocol(tcp.tcp)
            udp_pkt  = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if tcp_pkt:
                proto     = "TCP"
                src_port  = str(tcp_pkt.src_port)
                dst_port  = str(tcp_pkt.dst_port)
                tcp_flags = extract_flags(tcp_pkt)
            elif udp_pkt:
                proto    = "UDP"
                src_port = str(udp_pkt.src_port)
                dst_port = str(udp_pkt.dst_port)
            elif icmp_pkt:
                proto     = "ICMP"
                icmp_type = str(icmp_pkt.type)

        elif ip6:
            src_ip = ip6.src
            dst_ip = ip6.dst
            proto  = "IPv6"

            tcp_pkt   = pkt.get_protocol(tcp.tcp)
            udp_pkt   = pkt.get_protocol(udp.udp)
            icmp6_pkt = pkt.get_protocol(icmpv6.icmpv6)

            if tcp_pkt:
                proto     = "TCP"
                src_port  = str(tcp_pkt.src_port)
                dst_port  = str(tcp_pkt.dst_port)
                tcp_flags = extract_flags(tcp_pkt)
            elif udp_pkt:
                proto    = "UDP"
                src_port = str(udp_pkt.src_port)
                dst_port = str(udp_pkt.dst_port)
            elif icmp6_pkt:
                proto     = "ICMPv6"
                icmp_type = str(getattr(icmp6_pkt, 'type_', getattr(icmp6_pkt, 'type', '?')))

        pkt_len  = len(data)
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}"

        # ── Stats ──
        with self._lock:
            self._stats["total"] += 1
            self._stats["bytes"] += pkt_len
            self._flows.add(flow_key)
            self._stats["flows"] = len(self._flows)

        # ── CSV log ──
        self._csv.writerow([
            ts, dpid, in_port,
            eth_src, eth_dst, eth_type,
            proto, src_ip, dst_ip,
            src_port, dst_port, pkt_len,
            tcp_flags, ttl, icmp_type
        ])

        # ── Terminal output ──
        with self._lock:
            self._row_count += 1
            reprint = (self._row_count % BANNER_INTERVAL == 1 and self._row_count > 1)

        print(f"[{ts}] {src_ip} → {dst_ip} | {proto}")

        # ── L2 MAC learning & forwarding ─────────────────────────────
        if dp.id not in self.mac_to_port:
            self.mac_to_port[dp.id] = {}

        self.mac_to_port[dp.id][eth_src] = in_port      # learn src MAC → port

        out_port = self.mac_to_port[dp.id].get(eth_dst, ofp.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        # Install a flow rule once we know the destination port
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst, eth_src=eth_src)
            inst  = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod   = parser.OFPFlowMod(
                datapath=dp, priority=1,
                idle_timeout=30, hard_timeout=120,
                match=match, instructions=inst
            )
            dp.send_msg(mod)

        # Forward the current packet
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        )
        dp.send_msg(out)
