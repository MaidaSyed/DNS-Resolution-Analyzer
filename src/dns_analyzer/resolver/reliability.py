"""
reliability.py - How we talk to ONE nameserver reliably (feature F3).

UDP gives no delivery guarantee, so DnsTransport adds:
  * timeouts            - never wait forever for a reply
  * retransmission      - resend the same query if no reply arrived
  * exponential back-off- each wait is `backoff` times longer than the last,
                          so a congested/lossy path is not hammered
  * TCP fallback        - if the reply has the TC (truncated) bit, ask again
                          over TCP, which has no size limit
  * validation          - ignore replies with the wrong ID/question (stray or
                          spoofed packets) and keep waiting

Failover between SEVERAL nameservers is decided one level up, in
iterative.py, because only the resolver knows which servers are alternatives.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from dns_analyzer.clients.common import frame_message, is_usable, read_framed
from dns_analyzer.dns import DNSError, Message


class QueryFailure(Exception):
    """A server could not be queried successfully (the resolver may fail over)."""


class QueryTimeout(QueryFailure):
    """All retransmissions went unanswered."""


@dataclass
class Exchange:
    response: Message
    attempts: int          # UDP packets sent for this query (1 = no retransmission)
    rtt_ms: float          # time from the LAST send until the reply arrived
    elapsed_ms: float      # time from the FIRST send (includes waiting + TCP)
    used_tcp: bool = False
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class TransportStats:
    """Counters the benchmark reads (retransmissions are a required metric)."""
    queries: int = 0
    packets_sent: int = 0
    retransmissions: int = 0
    timeouts: int = 0
    tcp_fallbacks: int = 0
    failures: int = 0


class DnsTransport:
    def __init__(self, port: int = 53, timeout: float = 1.0, attempts: int = 3,
                 backoff: float = 2.0) -> None:
        self.port = port
        self.timeout = timeout      # wait after the first send
        self.attempts = attempts    # total UDP sends per query
        self.backoff = backoff      # timeout multiplier per retransmission
        self.stats = TransportStats()

    def exchange(self, server_ip: str, query: Message) -> Exchange:
        wire = query.to_bytes()
        self.stats.queries += 1
        started = time.perf_counter()
        try:
            exchange = self._udp(server_ip, query, wire, started)
            if exchange.response.flags.tc:
                self.stats.tcp_fallbacks += 1
                exchange = self._tcp(server_ip, query, wire, started, exchange)
            return exchange
        except QueryFailure:
            self.stats.failures += 1
            raise

    def _udp(self, ip: str, query: Message, wire: bytes, started: float) -> Exchange:
        received = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((ip, self.port))     # kernel now drops other sources
            for attempt in range(self.attempts):
                wait = self.timeout * (self.backoff ** attempt)
                try:
                    sock.send(wire)
                except OSError as exc:
                    raise QueryFailure(f"send failed: {exc}") from exc
                sent_at = time.perf_counter()
                self.stats.packets_sent += 1
                if attempt:
                    self.stats.retransmissions += 1
                deadline = time.monotonic() + wait
                while (remaining := deadline - time.monotonic()) > 0:
                    sock.settimeout(remaining)
                    try:
                        data = sock.recv(65535)
                    except socket.timeout:
                        break
                    except ConnectionRefusedError as exc:   # ICMP port unreachable
                        raise QueryFailure(f"{ip}:{self.port} refused the connection") from exc
                    except OSError as exc:
                        raise QueryFailure(f"receive failed: {exc}") from exc
                    received += len(data)
                    try:
                        reply = Message.from_bytes(data)
                    except DNSError:
                        continue                    # garbage packet: keep waiting
                    if is_usable(reply, query):
                        continue                    # wrong ID/question: ignore
                    now = time.perf_counter()
                    return Exchange(reply, attempt + 1, (now - sent_at) * 1000,
                                    (now - started) * 1000, False,
                                    len(wire) * (attempt + 1), received)
        self.stats.timeouts += 1
        raise QueryTimeout(f"no reply from {ip}:{self.port} after {self.attempts} attempt(s)")

    def _tcp(self, ip: str, query: Message, wire: bytes, started: float,
             udp: Exchange) -> Exchange:
        """Repeat the query over TCP (RFC 7766) because the UDP reply was truncated."""
        tcp_start = time.perf_counter()
        try:
            with socket.create_connection((ip, self.port), timeout=self.timeout * 2) as sock:
                framed = frame_message(wire)
                sock.sendall(framed)
                data = read_framed(sock)
        except OSError as exc:
            raise QueryFailure(f"TCP fallback to {ip}:{self.port} failed: {exc}") from exc
        try:
            reply = Message.from_bytes(data)
        except DNSError as exc:
            raise QueryFailure(f"bad TCP reply: {exc}") from exc
        problem = is_usable(reply, query)
        if problem:
            raise QueryFailure(f"bad TCP reply: {problem}")
        now = time.perf_counter()
        return Exchange(reply, udp.attempts, (now - tcp_start) * 1000,
                        (now - started) * 1000, True,
                        udp.bytes_sent + len(framed), udp.bytes_received + len(data) + 2)
