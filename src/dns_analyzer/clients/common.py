"""
common.py - Pieces shared by the Do53, DoT and DoH clients.

  * QueryResult : what every client returns, so the benchmark can treat all
                  methods the same way.
  * TCP framing : DNS over TCP/TLS prefixes every message with a 2-byte length
                  (RFC 1035 section 4.2.2, reused by RFC 7858).
"""
from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass

from dns_analyzer.dns import Message, Rcode


@dataclass
class QueryResult:
    """
    Outcome of one query. Clients never raise for network problems; they fill
    `error` instead, so a benchmark can count failures (success rate).

    Byte counters are DNS payload bytes (plus the 2-byte TCP length prefix
    where it applies). They do NOT include TCP/TLS/HTTP headers or handshakes;
    the true on-the-wire totals come from the packet captures (F8).
    """
    method: str
    response: Message | None = None
    query_time_ms: float = 0.0       # whole call, including any connection setup
    connect_ms: float = 0.0          # TCP three-way handshake (DoT only)
    tls_ms: float = 0.0              # TLS handshake (DoT only)
    reused_connection: bool = False
    bytes_sent: int = 0
    bytes_received: int = 0
    attempts: int = 1                # UDP sends (Do53); 1 for TCP-based methods
    used_tcp_fallback: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when a valid DNS response arrived (NXDOMAIN still counts)."""
        return self.response is not None and self.error is None

    @property
    def retransmissions(self) -> int:
        return max(self.attempts - 1, 0)

    @property
    def handshake_ms(self) -> float:
        return self.connect_ms + self.tls_ms

    @property
    def exchange_ms(self) -> float:
        """Time spent on the query/response itself, excluding handshakes."""
        return max(self.query_time_ms - self.handshake_ms, 0.0)

    @property
    def rcode(self) -> int | None:
        return self.response.rcode if self.response else None

    def summary_answers(self) -> list[str]:
        if not self.response:
            return []
        return [str(rr) for rr in self.response.answers]


def frame_message(wire: bytes) -> bytes:
    """Prefix a DNS message with its 2-byte big-endian length."""
    if len(wire) > 0xFFFF:
        raise ValueError("DNS message too large for TCP framing")
    return struct.pack("!H", len(wire)) + wire


def recv_exact(sock: socket.socket | ssl.SSLSocket, count: int) -> bytes:
    """
    Read exactly `count` bytes. TCP is a byte stream, so one recv() may return
    fewer bytes than requested; we loop until we have them all.
    """
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed by peer")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_framed(sock: socket.socket | ssl.SSLSocket) -> bytes:
    """Read one length-prefixed DNS message from a TCP/TLS socket."""
    (length,) = struct.unpack("!H", recv_exact(sock, 2))
    return recv_exact(sock, length)


def is_usable(response: Message, query: Message) -> str | None:
    """Return a problem description if `response` does not answer `query`."""
    if response.id != query.id:
        return f"response ID {response.id} does not match query ID {query.id}"
    if not response.flags.qr:
        return "reply does not have the QR (response) bit set"
    if response.questions and response.questions[0] != query.questions[0]:
        return "question section in reply does not match the query"
    return None
