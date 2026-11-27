"""
capture.py - Packet-capture analysis (feature F8).

Reads a .pcap file written by tcpdump (classic pcap format, Ethernet frames)
using only struct, and reports what the proposal asks for:

  * packets and bytes on the wire (handshakes and headers INCLUDED)
  * TCP handshake time        (client SYN -> server SYN/ACK)
  * TLS handshake time        (ClientHello -> client's Finished flight)
  * retransmissions           (TCP: same sequence range sent twice;
                               UDP DNS: same query ID sent twice from the same port)
  * a per-port breakdown (53 = Do53, 853 = DoT, 443 = DoH)

Everything here can be cross-checked in Wireshark (see README, "Packet capture").
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

LINKTYPE_ETHERNET, LINKTYPE_RAW_IP, LINKTYPE_LINUX_SLL = 1, 101, 113
TCP_FIN, TCP_SYN, TCP_ACK = 0x01, 0x02, 0x10
SERVICE_NAMES = {53: "Do53 (UDP/TCP 53)", 853: "DoT (TCP 853)", 443: "DoH (TCP 443)"}


class PcapError(Exception):
    pass


@dataclass
class Packet:
    ts: float                 # seconds since epoch
    wire_len: int             # original frame length (what was on the wire)
    src: str
    dst: str
    proto: int                # 6 = TCP, 17 = UDP
    sport: int
    dport: int
    flags: int = 0            # TCP flags
    seq: int = 0
    payload: bytes = b""


def read_pcap(path: str | Path) -> Iterator[Packet]:
    """Yield every IPv4 TCP/UDP packet of a pcap file (other packets are skipped)."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise PcapError("file is too short to be a pcap")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
               b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    if data[:4] not in formats:
        raise PcapError("not a classic pcap file (pcapng is not supported: use tcpdump -w)")
    endian, unit = formats[data[:4]]
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_frac, caplen, origlen = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset:offset + caplen]
        offset += caplen
        packet = _parse_frame(frame, linktype, ts_sec + ts_frac * unit, origlen)
        if packet:
            yield packet


def _parse_frame(frame: bytes, linktype: int, ts: float, wire_len: int) -> Packet | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype, start = struct.unpack_from("!H", frame, 12)[0], 14
        if ethertype == 0x8100 and len(frame) >= 18:        # skip a VLAN tag
            ethertype, start = struct.unpack_from("!H", frame, 16)[0], 18
        if ethertype != 0x0800:
            return None                                      # ARP, IPv6, ...
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16 or struct.unpack_from("!H", frame, 14)[0] != 0x0800:
            return None
        start = 16
    elif linktype == LINKTYPE_RAW_IP:
        start = 0
    else:
        raise PcapError(f"unsupported link type {linktype}")
    ip = frame[start:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total_len = struct.unpack_from("!H", ip, 2)[0]
    proto = ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    segment = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]    # drops Ethernet padding
    if proto == 17 and len(segment) >= 8:
        sport, dport = struct.unpack_from("!HH", segment, 0)
        return Packet(ts, wire_len, src, dst, 17, sport, dport, payload=bytes(segment[8:]))
    if proto == 6 and len(segment) >= 20:
        sport, dport, seq = struct.unpack_from("!HHI", segment, 0)
        data_offset = (segment[12] >> 4) * 4
        return Packet(ts, wire_len, src, dst, 6, sport, dport, flags=segment[13],
                      seq=seq, payload=bytes(segment[data_offset:]))
    return None


@dataclass
class CaptureSummary:
    packets: int = 0
    bytes: int = 0                        # sum of frame lengths (Ethernet + IP + TCP/UDP + data)
    packets_from_client: int = 0
    packets_from_servers: int = 0
    bytes_from_client: int = 0
    bytes_from_servers: int = 0
    tcp_connections: int = 0              # number of SYNs sent by the client (new connections)
    tcp_handshake_ms: list[float] = field(default_factory=list)
    tls_handshake_ms: list[float] = field(default_factory=list)
    tcp_retransmissions: int = 0
    udp_dns_retransmissions: int = 0
    duration_s: float = 0.0
    by_port: dict[int, list[int]] = field(default_factory=dict)   # server port -> [packets, bytes]

    @property
    def retransmissions(self) -> int:
        return self.tcp_retransmissions + self.udp_dns_retransmissions


def analyze_pcap(path: str | Path, client_ip: str = "10.10.1.10") -> CaptureSummary:
    summary = CaptureSummary()
    first_ts = last_ts = None
    seen_tcp: set[tuple] = set()                 # (src, sport, dst, dport, seq, length)
    seen_udp: set[tuple] = set()                 # (client port, server ip, dns id)
    syn_time: dict[tuple, float] = {}            # client-side flow -> first SYN time
    hello_time: dict[tuple, float] = {}          # flow -> ClientHello time
    tls_done: set[tuple] = set()
    hs_done: set[tuple] = set()

    for pkt in read_pcap(path):
        first_ts = pkt.ts if first_ts is None else first_ts
        last_ts = pkt.ts
        from_client = pkt.src == client_ip
        summary.packets += 1
        summary.bytes += pkt.wire_len
        if from_client:
            summary.packets_from_client += 1
            summary.bytes_from_client += pkt.wire_len
            server_port = pkt.dport
            flow = (pkt.sport, pkt.dst, pkt.dport)
        else:
            summary.packets_from_servers += 1
            summary.bytes_from_servers += pkt.wire_len
            server_port = pkt.sport
            flow = (pkt.dport, pkt.src, pkt.sport)
        counters = summary.by_port.setdefault(server_port, [0, 0])
        counters[0] += 1
        counters[1] += pkt.wire_len

        if pkt.proto == 17:
            if from_client and len(pkt.payload) >= 2:
                key = (pkt.sport, pkt.dst, struct.unpack_from("!H", pkt.payload, 0)[0])
                if key in seen_udp:
                    summary.udp_dns_retransmissions += 1
                seen_udp.add(key)
            continue

        # ---- TCP ----
        if pkt.payload or pkt.flags & (TCP_SYN | TCP_FIN):
            key = (pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.seq, len(pkt.payload))
            if key in seen_tcp:
                summary.tcp_retransmissions += 1
            seen_tcp.add(key)
        if from_client and pkt.flags & TCP_SYN and not pkt.flags & TCP_ACK:
            if flow not in syn_time:
                summary.tcp_connections += 1
                syn_time[flow] = pkt.ts
        elif not from_client and pkt.flags & TCP_SYN and pkt.flags & TCP_ACK:
            if flow in syn_time and flow not in hs_done:
                hs_done.add(flow)
                summary.tcp_handshake_ms.append((pkt.ts - syn_time[flow]) * 1000)
        if from_client and len(pkt.payload) >= 6 and flow not in tls_done:
            record_type = pkt.payload[0]
            if flow not in hello_time:
                if record_type == 0x16 and pkt.payload[5] == 0x01:          # ClientHello
                    hello_time[flow] = pkt.ts
            elif record_type in (0x14, 0x17):       # ChangeCipherSpec / encrypted Finished
                tls_done.add(flow)
                summary.tls_handshake_ms.append((pkt.ts - hello_time[flow]) * 1000)

    if first_ts is not None:
        summary.duration_s = last_ts - first_ts
    return summary


def format_summary(summary: CaptureSummary, queries: int | None = None) -> str:
    def mean(values: list[float]) -> str:
        return f"{sum(values) / len(values):.2f} ms (n={len(values)})" if values else "n/a"

    lines = [f"packets: {summary.packets}   bytes on the wire: {summary.bytes}   "
             f"duration: {summary.duration_s:.2f} s",
             f"  client -> servers: {summary.packets_from_client} packets, {summary.bytes_from_client} bytes",
             f"  servers -> client: {summary.packets_from_servers} packets, {summary.bytes_from_servers} bytes",
             f"TCP connections opened: {summary.tcp_connections}",
             f"TCP handshake time (SYN -> SYN/ACK): {mean(summary.tcp_handshake_ms)}",
             f"TLS handshake time (ClientHello -> client Finished): {mean(summary.tls_handshake_ms)}",
             f"retransmissions: {summary.retransmissions} "
             f"(TCP {summary.tcp_retransmissions}, UDP DNS {summary.udp_dns_retransmissions})"]
    for port, (pkts, size) in sorted(summary.by_port.items()):
        lines.append(f"  server port {port:<5} {SERVICE_NAMES.get(port, ''):<20} {pkts} packets, {size} bytes")
    if queries:
        lines.append(f"per query: {summary.packets / queries:.1f} packets, {summary.bytes / queries:.0f} bytes")
    return "\n".join(lines)
