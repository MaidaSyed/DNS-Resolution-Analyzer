"""
dot.py - DNS over TLS client (RFC 7858): TCP port 853, TLS 1.3.

Wire format inside the TLS stream is identical to DNS over TCP: each message
is preceded by a 2-byte length. The TLS session is kept open between queries
(connection reuse), so only the FIRST query pays for the TCP + TLS handshakes.
"""
from __future__ import annotations

import socket
import ssl
import time

from dns_analyzer.dns import DNSError, Message, RType, make_query

from .common import QueryResult, frame_message, is_usable, read_framed


def build_tls_context(cafile: str | None = None, insecure: bool = False,
                      alpn: list[str] | None = None) -> ssl.SSLContext:
    """TLS client context that refuses anything older than TLS 1.3."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if insecure:                                   # lab use only; no verification
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


class DoTClient:
    method = "dot"

    def __init__(self, server: str, port: int = 853, server_hostname: str | None = None,
                 cafile: str | None = None, insecure: bool = False,
                 timeout: float = 5.0) -> None:
        self.server = server
        self.port = port
        # Name checked against the certificate (also sent as SNI). For an IP
        # address Python checks the certificate's IP SAN entry instead.
        self.server_hostname = server_hostname or server
        self.timeout = timeout
        self._ctx = build_tls_context(cafile, insecure)
        self._sock: ssl.SSLSocket | None = None
        self.tls_version: str | None = None
        self.cipher: str | None = None

    # -- connection management ------------------------------------------
    def _connect(self) -> tuple[float, float]:
        """Open TCP, then TLS. Returns (tcp_ms, tls_ms)."""
        t0 = time.perf_counter()
        raw = socket.create_connection((self.server, self.port), timeout=self.timeout)
        t1 = time.perf_counter()                   # TCP handshake finished
        # Request/response protocol with small writes: disable Nagle's
        # algorithm so a query is sent immediately, not held for an ACK.
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            tls = self._ctx.wrap_socket(raw, server_hostname=self.server_hostname)
        except Exception:
            raw.close()
            raise
        t2 = time.perf_counter()                   # TLS handshake finished
        tls.settimeout(self.timeout)
        self._sock = tls
        self.tls_version = tls.version()
        cipher = tls.cipher()
        self.cipher = cipher[0] if cipher else None
        return (t1 - t0) * 1000, (t2 - t1) * 1000

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "DoTClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- queries ---------------------------------------------------------
    def query(self, name: str, qtype: int = RType.A, rd: bool = True) -> QueryResult:
        query = make_query(name, qtype, rd=rd)
        framed = frame_message(query.to_bytes())
        result = QueryResult(method=self.method)
        start = time.perf_counter()
        try:
            try:
                reply = self._send_receive(query, framed, result)
            except (OSError, DNSError) as exc:
                if not result.reused_connection:
                    raise
                # An idle connection may have been closed by the server.
                # Retry once on a brand-new connection.
                self.close()
                result.bytes_sent = result.bytes_received = 0
                result.reused_connection = False
                reply = self._send_receive(query, framed, result)
            result.response = reply
        except socket.timeout:
            self.close()
            result.error = "timeout"
        except (OSError, DNSError, ValueError) as exc:
            self.close()
            result.error = f"{type(exc).__name__}: {exc}"
        result.query_time_ms = (time.perf_counter() - start) * 1000
        return result

    def _send_receive(self, query: Message, framed: bytes, result: QueryResult) -> Message:
        if self._sock is None:
            result.connect_ms, result.tls_ms = self._connect()
            result.reused_connection = False
        else:
            result.reused_connection = True
        self._sock.sendall(framed)
        result.bytes_sent += len(framed)
        data = read_framed(self._sock)
        result.bytes_received += len(data) + 2
        reply = Message.from_bytes(data)
        problem = is_usable(reply, query)
        if problem:
            raise ValueError(problem)
        return reply