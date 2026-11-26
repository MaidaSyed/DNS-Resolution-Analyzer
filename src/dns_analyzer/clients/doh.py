"""
doh.py - DNS over HTTPS client (RFC 8484): HTTP/2 POST over TLS 1.3, port 443.

The DNS message is sent as the raw request body with
    content-type: application/dns-message
and the answer comes back as the raw response body with the same type.
One httpx.Client is kept alive, so HTTP/2 multiplexes every query over a
single TLS connection (connection reuse).
"""
from __future__ import annotations

import time

import httpx

from dns_analyzer.dns import DNSError, Message, RType, make_query

from .common import QueryResult, is_usable
from .dot import build_tls_context

DNS_MESSAGE = "application/dns-message"


class DoHClient:
    method = "doh"

    def __init__(self, url: str, cafile: str | None = None, insecure: bool = False,
                 timeout: float = 5.0, sni_hostname: str | None = None) -> None:
        self.url = url
        self.timeout = timeout
        # Use when the URL contains an IP address but the certificate is for a
        # hostname: SNI and certificate checking then use this name.
        self.sni_hostname = sni_hostname
        self._client = httpx.Client(
            http2=True,
            verify=build_tls_context(cafile, insecure),   # TLS 1.3 only
            timeout=timeout,
        )
        self._last_stream = None      # underlying connection of the previous query
        self.http_version: str | None = None

    def close(self) -> None:
        self._client.close()
        self._last_stream = None

    def __enter__(self) -> "DoHClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def query(self, name: str, qtype: int = RType.A, rd: bool = True) -> QueryResult:
        # RFC 8484 section 4.1: use ID 0 so identical questions give identical
        # HTTP bodies (cache friendly). HTTPS already protects against spoofing.
        query = make_query(name, qtype, rd=rd, msg_id=0)
        wire = query.to_bytes()
        result = QueryResult(method=self.method, bytes_sent=len(wire))
        extensions = {"sni_hostname": self.sni_hostname} if self.sni_hostname else {}
        start = time.perf_counter()
        try:
            response = self._client.post(
                self.url, content=wire, extensions=extensions,
                headers={"content-type": DNS_MESSAGE, "accept": DNS_MESSAGE},
            )
            self.http_version = response.http_version
            stream = response.extensions.get("network_stream")
            result.reused_connection = stream is not None and stream is self._last_stream
            self._last_stream = stream
            if response.status_code != 200:
                raise ValueError(f"HTTP status {response.status_code}")
            if not response.headers.get("content-type", "").startswith(DNS_MESSAGE):
                raise ValueError("response content-type is not application/dns-message")
            if response.http_version != "HTTP/2":
                raise ValueError(f"expected HTTP/2 but server used {response.http_version}")
            result.bytes_received = len(response.content)
            reply = Message.from_bytes(response.content)
            problem = is_usable(reply, query)
            if problem:
                raise ValueError(problem)
            result.response = reply
        except httpx.TimeoutException:
            result.error = "timeout"
        except (httpx.HTTPError, OSError, DNSError, ValueError) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
        result.query_time_ms = (time.perf_counter() - start) * 1000
        return result