"""
Tests for the Do53, DoT and DoH clients (F4, F5) against local fake servers.
Run:  pytest tests/test_clients.py -v
"""
import shutil
import socket

import pytest

from dns_analyzer.clients import Do53Client, DoHClient, DoTClient
from dns_analyzer.clients.common import frame_message, read_framed
from fake_servers import (ANSWER_IP, FakeDo53Server, FakeDoHServer, FakeDoTServer,
                          make_self_signed_cert)

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                   reason="openssl CLI not installed")


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    return make_self_signed_cert(tmp_path_factory.mktemp("certs"))


def first_answer(result):
    return result.response.answers[0].rdata


# ------------------------------------------------------------- framing ----
def test_framing_roundtrip_with_split_reads():
    a, b = socket.socketpair()
    with a, b:
        data = frame_message(b"hello-dns")
        assert data[:2] == b"\x00\x09"
        a.sendall(data[:3])                 # deliver in two pieces
        a.sendall(data[3:])
        assert read_framed(b) == b"hello-dns"


# ---------------------------------------------------------------- Do53 ----
def test_do53_success():
    with FakeDo53Server() as srv:
        res = Do53Client("127.0.0.1", srv.port, timeout=1).query("www.example.test")
    assert res.ok and res.attempts == 1 and res.retransmissions == 0
    assert first_answer(res) == ANSWER_IP
    assert res.response.flags.rd and res.bytes_sent > 12 and res.bytes_received > 12


def test_do53_retransmits_after_loss():
    with FakeDo53Server(drop_first=2) as srv:        # first 2 packets "lost"
        res = Do53Client("127.0.0.1", srv.port, timeout=0.1, attempts=3).query("a.example.test")
    assert res.ok and res.attempts == 3 and res.retransmissions == 2
    assert res.query_time_ms >= 100 + 200 - 30       # waited 0.1 s then 0.2 s


def test_do53_gives_up_when_everything_is_lost():
    with FakeDo53Server(drop_first=99) as srv:
        res = Do53Client("127.0.0.1", srv.port, timeout=0.05, attempts=2).query("a.example.test")
    assert not res.ok and "timeout" in res.error and res.attempts == 2


def test_do53_falls_back_to_tcp_when_truncated():
    with FakeDo53Server(truncate=True) as srv:
        res = Do53Client("127.0.0.1", srv.port, timeout=1).query("www.example.test")
    assert res.ok and res.used_tcp_fallback
    assert first_answer(res) == ANSWER_IP            # full answer came via TCP


def test_do53_reports_error_when_port_closed():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    res = Do53Client("127.0.0.1", port, timeout=0.2, attempts=1).query("a.test")
    assert not res.ok and res.error


# ----------------------------------------------------------------- DoT ----
@needs_openssl
def test_dot_first_query_has_handshake_then_connection_is_reused(cert):
    with FakeDoTServer(*cert) as srv:
        with DoTClient("127.0.0.1", srv.port, cafile=cert[0]) as client:
            first = client.query("a.example.test")
            second = client.query("b.example.test")
            assert client.tls_version == "TLSv1.3"
        assert first.ok and first_answer(first) == ANSWER_IP
        assert not first.reused_connection and first.connect_ms > 0 and first.tls_ms > 0
        assert second.ok and second.reused_connection and second.handshake_ms == 0
        assert srv.connections == 1 and srv.queries == 2


@needs_openssl
def test_dot_reconnects_after_server_closes_connection(cert):
    with FakeDoTServer(*cert) as srv:
        with DoTClient("127.0.0.1", srv.port, cafile=cert[0]) as client:
            assert client.query("a.example.test").ok
            srv.close_all()
            again = client.query("b.example.test")
        assert again.ok and not again.reused_connection
        assert srv.connections == 2


@needs_openssl
def test_dot_rejects_untrusted_certificate_but_insecure_flag_allows_it(cert):
    with FakeDoTServer(*cert) as srv:
        strict = DoTClient("127.0.0.1", srv.port).query("a.example.test")   # no CA given
        assert not strict.ok and "CERTIFICATE_VERIFY_FAILED" in strict.error
        lax = DoTClient("127.0.0.1", srv.port, insecure=True).query("a.example.test")
        assert lax.ok


def test_dot_connection_refused_is_an_error_not_an_exception():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    res = DoTClient("127.0.0.1", port, insecure=True, timeout=0.5).query("a.test")
    assert not res.ok and res.error


# ----------------------------------------------------------------- DoH ----
@needs_openssl
def test_doh_uses_http2_post_and_reuses_the_connection(cert):
    with FakeDoHServer(*cert) as srv:
        with DoHClient(f"https://127.0.0.1:{srv.port}/dns-query", cafile=cert[0]) as client:
            first = client.query("a.example.test")
            second = client.query("b.example.test")
            assert client.http_version == "HTTP/2"
        assert first.ok and first_answer(first) == ANSWER_IP
        assert not first.reused_connection and second.reused_connection
        assert srv.connections == 1 and len(srv.requests) == 2
        headers = srv.requests[0]["headers"]
        assert headers[":method"] == "POST"
        assert headers["content-type"] == "application/dns-message"
        assert headers["accept"] == "application/dns-message"
        assert srv.requests[0]["body"][:2] == b"\x00\x00"      # DNS ID 0 (RFC 8484)


@needs_openssl
def test_doh_rejects_untrusted_certificate(cert):
    with FakeDoHServer(*cert) as srv:
        with DoHClient(f"https://127.0.0.1:{srv.port}/dns-query") as client:
            res = client.query("a.example.test")
    assert not res.ok and "CERTIFICATE_VERIFY_FAILED" in res.error


@needs_openssl
def test_doh_reports_http_errors(cert):
    with FakeDoHServer(*cert, status=500) as srv:
        with DoHClient(f"https://127.0.0.1:{srv.port}/dns-query", cafile=cert[0]) as client:
            res = client.query("a.example.test")
    assert not res.ok and "500" in res.error