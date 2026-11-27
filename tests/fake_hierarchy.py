"""
fake_hierarchy.py - A miniature DNS tree on 127.0.0.x for testing the resolver.

    root  127.0.0.10   zone "."            delegates test.
    tld   127.0.0.20   zone "test."        delegates example.test. and noglue.test.
    auth  127.0.0.30   zones example.test. + noglue.test.
    auth2 127.0.0.31   zone  example.test. (second nameserver, for failover)

All servers listen on the same port number (the resolver takes ONE port
setting), each on its own loopback address. Linux treats all of 127.0.0.0/8 as
loopback, so no setup or root rights are needed.
"""
from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field

from dns_analyzer.clients.common import frame_message, read_framed
from dns_analyzer.dns import (Flags, Message, Question, Rcode, ResourceRecord, RType,
                              SoaData)

ROOT_IP, TLD_IP, AUTH_IP, AUTH2_IP = "127.0.0.10", "127.0.0.20", "127.0.0.30", "127.0.0.31"


def _under(child: str, parent: str) -> bool:
    return parent == "." or child == parent or child.endswith("." + parent)


@dataclass
class Zone:
    origin: str
    records: list[ResourceRecord] = field(default_factory=list)
    # cut -> [(NS name, glue IP or None)]. None means a referral WITHOUT glue.
    delegations: dict[str, list[tuple[str, str | None]]] = field(default_factory=dict)

    def soa(self) -> ResourceRecord:
        return ResourceRecord(self.origin, RType.SOA, 60, SoaData(
            f"ns.{self.origin}".replace("..", "."), f"admin.{self.origin}".replace("..", "."),
            1, 3600, 600, 86400, 60))


class FakeNameServer:
    """Authoritative server over UDP and TCP with switchable faults."""

    def __init__(self, ip: str, port: int, zones: list[Zone], *, drop_first: int = 0,
                 truncate_udp: bool = False, mode: str = "normal",
                 include_cname_targets: bool = True) -> None:
        self.ip, self.port, self.zones = ip, port, zones
        self.drop_first = drop_first                  # lose the first N UDP queries
        self.truncate_udp = truncate_udp              # UDP: set TC; TCP: full answer
        self.mode = mode                              # normal | dead | servfail
        self.include_cname_targets = include_cname_targets
        self.log: list[tuple[str, int, bool, str]] = []   # (qname, qtype, rd, "udp"/"tcp")
        self._stop = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((ip, port))
        self.udp.settimeout(0.1)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((ip, port))
        self.tcp.listen(8)
        self.tcp.settimeout(0.1)
        self._threads = [threading.Thread(target=self._udp_loop, daemon=True),
                         threading.Thread(target=self._tcp_loop, daemon=True)]

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        for t in self._threads:
            t.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self.udp.close()
        self.tcp.close()

    # -- network loops -----------------------------------------------------
    def _udp_loop(self) -> None:
        seen = 0
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            seen += 1
            if self.mode == "dead" or seen <= self.drop_first:
                continue
            query = Message.from_bytes(data)
            q = query.questions[0]
            self.log.append((q.name, q.qtype, query.flags.rd, "udp"))
            reply = self.answer(query)
            if self.truncate_udp:
                reply = Message(id=query.id, flags=Flags(qr=True, aa=True, tc=True),
                                questions=query.questions)
            self.udp.sendto(reply.to_bytes(), addr)

    def _tcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                try:
                    query = Message.from_bytes(read_framed(conn))
                    q = query.questions[0]
                    self.log.append((q.name, q.qtype, query.flags.rd, "tcp"))
                    conn.sendall(frame_message(self.answer(query).to_bytes()))
                except (OSError, ConnectionError):
                    pass

    # -- DNS logic -----------------------------------------------------------
    def answer(self, query: Message) -> Message:
        q = query.questions[0]
        reply = Message(id=query.id, flags=Flags(qr=True, rd=query.flags.rd),
                        questions=[Question(q.name, q.qtype, q.qclass)], edns=query.edns)
        if self.mode == "servfail":
            reply.flags.rcode = Rcode.SERVFAIL
            return reply
        zone = self._best_zone(q.name)
        if zone is None:
            reply.flags.rcode = Rcode.REFUSED
            return reply

        for cut in sorted(zone.delegations, key=len, reverse=True):   # referral?
            if _under(q.name, cut) and cut != zone.origin:
                for ns, glue_ip in zone.delegations[cut]:
                    reply.authorities.append(ResourceRecord(cut, RType.NS, 3600, ns))
                    if glue_ip:
                        reply.additionals.append(ResourceRecord(ns, RType.A, 3600, glue_ip))
                return reply                                  # aa=0 for referrals

        reply.flags.aa = True
        here = [rr for rr in zone.records if rr.name == q.name]
        cname = [rr for rr in here if rr.rtype == RType.CNAME]
        if cname and q.qtype != RType.CNAME:
            reply.answers.append(cname[0])
            if self.include_cname_targets:
                target_zone = self._best_zone(cname[0].rdata)
                if target_zone:
                    reply.answers += [rr for rr in target_zone.records
                                      if rr.name == cname[0].rdata and rr.rtype == q.qtype]
            return reply
        wanted = [rr for rr in here if rr.rtype == q.qtype]
        if wanted:
            reply.answers = wanted
        else:
            if not here:
                reply.flags.rcode = Rcode.NXDOMAIN
            reply.authorities.append(zone.soa())
        return reply

    def _best_zone(self, name: str) -> Zone | None:
        matches = [z for z in self.zones if _under(name, z.origin)]
        return max(matches, key=lambda z: len(z.origin), default=None)


def pick_free_port() -> int:
    """A port number free for BOTH udp and tcp on the 127.0.0.x addresses."""
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.bind((ROOT_IP, 0))
            port = u.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
                t.bind((ROOT_IP, port))
            return port
        except OSError:
            continue
    raise RuntimeError("could not find a free port")


def rr(name, rtype, rdata, ttl=300):
    return ResourceRecord(name, rtype, ttl, rdata)


class Hierarchy:
    """Builds and owns the whole fake tree. Use as a context manager."""

    def __init__(self, *, auth_kwargs=None, auth2_kwargs=None, tld_kwargs=None,
                 root_kwargs=None, auth2=False, self_referring_root=False) -> None:
        self.port = pick_free_port()
        root_glue = ROOT_IP if self_referring_root else TLD_IP   # buggy root refers to itself
        root = Zone(".", [rr(".", RType.NS, "a.root."), rr("a.root.", RType.A, ROOT_IP)],
                    {"test.": [("ns.test.", root_glue)]})
        example_ns = [("ns1.example.test.", AUTH_IP)]
        if auth2:
            example_ns.append(("ns2.example.test.", AUTH2_IP))
        tld = Zone("test.", [rr("test.", RType.NS, "ns.test."), rr("ns.test.", RType.A, TLD_IP)],
                   {"example.test.": example_ns,
                    "noglue.test.": [("ns1.example.test.", None)]})   # referral WITHOUT glue
        example_records = [
            rr("example.test.", RType.NS, "ns1.example.test."),
            rr("ns1.example.test.", RType.A, AUTH_IP),
            rr("www.example.test.", RType.A, "10.10.3.30"),
            rr("alias.example.test.", RType.CNAME, "www.example.test."),
            rr("ext.example.test.", RType.CNAME, "host.noglue.test."),
            rr("loop1.example.test.", RType.CNAME, "loop2.example.test."),
            rr("loop2.example.test.", RType.CNAME, "loop1.example.test."),
        ]
        noglue_records = [rr("noglue.test.", RType.NS, "ns1.example.test."),
                          rr("host.noglue.test.", RType.A, "10.10.9.9")]
        self.servers = {
            "root": FakeNameServer(ROOT_IP, self.port, [root], **(root_kwargs or {})),
            "tld": FakeNameServer(TLD_IP, self.port, [tld], **(tld_kwargs or {})),
            "auth": FakeNameServer(AUTH_IP, self.port, [
                Zone("example.test.", example_records), Zone("noglue.test.", noglue_records)],
                **(auth_kwargs or {})),
        }
        if auth2:
            self.servers["auth2"] = FakeNameServer(
                AUTH2_IP, self.port, [Zone("example.test.", example_records)],
                **(auth2_kwargs or {}))

    def __enter__(self):
        for s in self.servers.values():
            s.start()
        return self

    def __exit__(self, *exc) -> None:
        for s in self.servers.values():
            s.stop()