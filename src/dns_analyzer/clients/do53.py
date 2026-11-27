"""
do53.py - Traditional DNS ("Do53") stub client: UDP/53 to a RECURSIVE resolver.

We set RD=1 (recursion desired) and let the resolver do the root/TLD/
authoritative walk. If the reply has the TC bit, we retry the same question
over TCP/53 (RFC 7766).

Reliability here is deliberately simple (a stub resolver's job): resend the
same packet with a doubling timeout. The full reliability engine for our own
iterative resolver (NS failover etc.) lives in resolver/reliability.py.
"""
from __future__ import annotations

import socket
import time

from dns_analyzer.dns import DNSError, Message, RType, make_query

from .common import QueryResult, frame_message, is_usable, read_framed


class Do53Client:
    method = "do53"

    def __init__(self, server: str, port: int = 53, timeout: float = 2.0,
                 attempts: int = 3, backoff: float = 2.0,
                 udp_payload_size: int = 1232) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout          # wait before the FIRST retransmission
        self.attempts = attempts        # total UDP sends before giving up
        self.backoff = backoff          # timeout multiplier per attempt
        self.udp_payload_size = udp_payload_size

    def query(self, name: str, qtype: int = RType.A, rd: bool = True) -> QueryResult:
        query = make_query(name, qtype, rd=rd, udp_payload_size=self.udp_payload_size)
        wire = query.to_bytes()
        result = QueryResult(method=self.method, attempts=0)
        start = time.perf_counter()
        try:
            reply = self._udp_exchange(query, wire, result)
            if reply.flags.tc:                       # truncated: ask again over TCP
                result.used_tcp_fallback = True
                reply = self._tcp_exchange(query, wire, result)
            result.response = reply
        except socket.timeout:
            result.error = f"timeout after {result.attempts} attempt(s)"
        except (OSError, DNSError, ValueError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        result.query_time_ms = (time.perf_counter() - start) * 1000
        return result

    def _udp_exchange(self, query: Message, wire: bytes, result: QueryResult) -> Message:
        """Send over UDP, retransmitting with exponential back-off."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # connect() on UDP sets a default peer: the kernel then drops
            # packets from any other source address for us.
            sock.connect((self.server, self.port))
            for attempt in range(self.attempts):
                wait = self.timeout * (self.backoff ** attempt)
                sock.send(wire)
                result.attempts += 1
                result.bytes_sent += len(wire)
                deadline = time.monotonic() + wait
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break                        # this attempt timed out
                    sock.settimeout(remaining)
                    try:
                        data = sock.recv(65535)
                    except socket.timeout:
                        break
                    result.bytes_received += len(data)
                    try:
                        reply = Message.from_bytes(data)
                    except DNSError:
                        continue                     # garbage: keep waiting
                    if is_usable(reply, query):
                        continue                     # wrong ID etc.: ignore it
                    return reply
            raise socket.timeout()

    def _tcp_exchange(self, query: Message, wire: bytes, result: QueryResult) -> Message:
        with socket.create_connection((self.server, self.port), timeout=self.timeout * 2) as sock:
            framed = frame_message(wire)
            sock.sendall(framed)
            result.bytes_sent += len(framed)
            data = read_framed(sock)
            result.bytes_received += len(data) + 2
        reply = Message.from_bytes(data)
        problem = is_usable(reply, query)
        if problem:
            raise ValueError(problem)
        return reply
