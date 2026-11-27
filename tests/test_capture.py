"""Tests for the pcap analysis (F8) using hand-built packets. Run: pytest tests/test_capture.py -v"""
import socket
import struct

import pytest

from dns_analyzer.benchmark.capture import (PcapError, analyze_pcap, format_summary, read_pcap)

CLIENT, RESOLVER = "10.10.1.10", "10.10.2.53"
SYN, ACK, PSH = 0x02, 0x10, 0x08


def ip_packet(proto, src, dst, l4):
    total = 20 + len(l4)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + l4


def frame(ip, padding=b""):
    return b"\x00" * 12 + b"\x08\x00" + ip + padding


def tcp(src, dst, sport, dport, flags, seq=0, payload=b""):
    l4 = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 1000, 0, 0) + payload
    return frame(ip_packet(6, src, dst, l4))


def udp(src, dst, sport, dport, payload):
    l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return frame(ip_packet(17, src, dst, l4))


def write_pcap(path, packets, *, big_endian=False, nano=False):
    e = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for ts, data in packets:
        sec = int(ts)
        frac = round((ts - sec) * (1e9 if nano else 1e6))
        out += struct.pack(e + "IIII", sec, frac, len(data), len(data)) + data
    path.write_bytes(out)
    return path


def test_counts_bytes_and_ports(tmp_path):
    f1 = udp(CLIENT, RESOLVER, 40000, 53, b"\x12\x34" + b"q" * 20)
    f2 = udp(RESOLVER, CLIENT, 53, 40000, b"\x12\x34" + b"r" * 40)
    arp = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 28
    path = write_pcap(tmp_path / "a.pcap", [(1.0, f1), (1.1, f2), (1.2, arp)])
    s = analyze_pcap(path)
    assert (s.packets, s.packets_from_client, s.packets_from_servers) == (2, 1, 1)
    assert s.bytes == len(f1) + len(f2)                 # ARP ignored
    assert s.by_port == {53: [2, len(f1) + len(f2)]}
    assert s.duration_s == pytest.approx(0.1)
    assert s.retransmissions == 0


def test_udp_dns_retransmission_detected(tmp_path):
    q = udp(CLIENT, RESOLVER, 40000, 53, b"\xab\xcd" + b"q" * 10)
    other_id = udp(CLIENT, RESOLVER, 40000, 53, b"\xab\xce" + b"q" * 10)
    path = write_pcap(tmp_path / "u.pcap", [(1.0, q), (2.0, q), (3.0, q), (3.1, other_id)])
    s = analyze_pcap(path)
    assert s.udp_dns_retransmissions == 2 and s.tcp_retransmissions == 0


def test_tcp_retransmission_detected_but_pure_acks_ignored(tmp_path):
    data = tcp(CLIENT, RESOLVER, 5000, 853, PSH | ACK, seq=100, payload=b"hello")
    ack = tcp(RESOLVER, CLIENT, 853, 5000, ACK, seq=1)
    path = write_pcap(tmp_path / "t.pcap", [(1.0, data), (1.001, ack), (1.2, data), (1.3, ack), (1.4, ack)])
    s = analyze_pcap(path)
    assert s.tcp_retransmissions == 1


def test_tcp_handshake_time_and_syn_retransmission(tmp_path):
    syn = tcp(CLIENT, RESOLVER, 5000, 853, SYN, seq=7)
    synack = tcp(RESOLVER, CLIENT, 853, 5000, SYN | ACK, seq=9)
    path = write_pcap(tmp_path / "h.pcap", [(1.000, syn), (2.000, syn), (2.020, synack)])
    s = analyze_pcap(path)
    assert s.tcp_connections == 1
    assert s.tcp_retransmissions == 1                      # the repeated SYN
    assert s.tcp_handshake_ms == [pytest.approx(1020.0)]   # measured from the FIRST SYN


def test_tls_handshake_time(tmp_path):
    hello = b"\x16\x03\x01\x00\x20\x01" + b"\x00" * 30           # record type 22, ClientHello
    finished = b"\x14\x03\x03\x00\x01\x01" + b"\x17\x03\x03\x00\x20" + b"\x00" * 32
    path = write_pcap(tmp_path / "tls.pcap", [
        (1.000, tcp(CLIENT, RESOLVER, 5000, 853, SYN)),
        (1.020, tcp(RESOLVER, CLIENT, 853, 5000, SYN | ACK)),
        (1.021, tcp(CLIENT, RESOLVER, 5000, 853, PSH | ACK, 1, hello)),
        (1.045, tcp(CLIENT, RESOLVER, 5000, 853, PSH | ACK, 1 + len(hello), finished)),
    ])
    s = analyze_pcap(path)
    assert s.tcp_handshake_ms == [pytest.approx(20.0)]
    assert s.tls_handshake_ms == [pytest.approx(24.0)]


def test_two_connections_counted_separately(tmp_path):
    pk = []
    for i, sport in enumerate((5000, 5001)):
        t = 1 + i
        pk += [(t, tcp(CLIENT, RESOLVER, sport, 443, SYN)),
               (t + 0.01, tcp(RESOLVER, CLIENT, 443, sport, SYN | ACK))]
    s = analyze_pcap(write_pcap(tmp_path / "c.pcap", pk))
    assert s.tcp_connections == 2 and len(s.tcp_handshake_ms) == 2


def test_ethernet_padding_not_counted_as_payload(tmp_path):
    f = tcp(CLIENT, RESOLVER, 5000, 853, PSH | ACK, 1, b"ab")
    padded = f + b"\x00" * 6                                       # Ethernet minimum-size padding
    pkt = next(read_pcap(write_pcap(tmp_path / "p.pcap", [(1.0, padded)])))
    assert pkt.payload == b"ab"


@pytest.mark.parametrize("big_endian,nano", [(False, False), (True, False), (False, True), (True, True)])
def test_all_pcap_byte_orders_and_time_units(tmp_path, big_endian, nano):
    f = udp(CLIENT, RESOLVER, 1, 53, b"\x00\x01xx")
    path = write_pcap(tmp_path / "e.pcap", [(100.5, f)], big_endian=big_endian, nano=nano)
    pkt = next(read_pcap(path))
    assert pkt.ts == pytest.approx(100.5) and pkt.dport == 53


def test_bad_files_are_rejected(tmp_path):
    (tmp_path / "short").write_bytes(b"abc")
    with pytest.raises(PcapError):
        list(read_pcap(tmp_path / "short"))
    (tmp_path / "ng").write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapError):
        list(read_pcap(tmp_path / "ng"))


def test_empty_capture_and_text_summary(tmp_path):
    path = write_pcap(tmp_path / "empty.pcap", [])
    s = analyze_pcap(path)
    assert s.packets == 0 and s.duration_s == 0
    text = format_summary(s)
    assert "packets: 0" in text and "n/a" in text
