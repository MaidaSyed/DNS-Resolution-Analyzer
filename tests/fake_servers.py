"""
fake_servers.py - Tiny local DNS servers used ONLY by the tests.

They answer every A query with 10.10.3.30, built with our own codec, and let
tests inject faults (dropped packets, truncation, closed connections).
No root privileges and no network namespaces are needed.
"""
from __future__ import annotations

import socket
import ssl
import subprocess
import threading

import h2.config
import h2.connection
import h2.events

from dns_analyzer.dns import Flags, Message, ResourceRecord, RType
from dns_analyzer.clients.common import frame_message, read_framed

ANSWER_IP = "10.10.3.30"


def answer_for(query: Message, truncate: bool = False) -> bytes:
    flags = Flags(qr=True, aa=True, rd=query.flags.rd, ra=True, tc=truncate)
    answers = [] if truncate else [
        ResourceRecord(query.questions[0].name, RType.A, 300, ANSWER_IP)]
    return Message(id=query.id, flags=flags, questions=query.questions,
                   answers=answers, edns=query.edns).to_bytes()


def make_self_signed_cert(directory) -> tuple[str, str]:
    """Create a throw-away EC certificate valid for localhost / 127.0.0.1."""
    cert, key = str(directory / "cert.pem"), str(directory / "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
         "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key, "-out", cert,
         "-days", "2", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        check=True, capture_output=True)
    return cert, key


def _server_tls_context(cert: str, key: str, alpn: list[str] | None = None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx


class _ThreadedServer:
    """Base: a listening TCP socket plus an accept loop in a daemon thread."""

    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.connections = 0
        self._stop = threading.Event()
        self._conns: list[socket.socket] = []
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self.close_all()
        self._thread.join(timeout=2)
        self.listener.close()

    def close_all(self) -> None:
        """Abruptly close every open client connection."""
        for conn in list(self._conns):
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        self._conns.clear()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._wrap_and_serve, args=(conn,), daemon=True).start()

    def _wrap_and_serve(self, conn) -> None:
        # Without TCP_NODELAY the TLS 1.3 session-ticket writes + Nagle's
        # algorithm + the client's delayed ACK add a fake ~40 ms stall.
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            conn = self._wrap(conn)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        self.connections += 1
        self._conns.append(conn)
        try:
            self._serve(conn)
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()

    def _wrap(self, conn):
        return conn

    def _serve(self, conn) -> None:
        raise NotImplementedError


class FakeDo53Server(_ThreadedServer):
    """UDP + TCP on the same port number. Faults: drop_first, truncate."""

    def __init__(self, drop_first: int = 0, truncate: bool = False) -> None:
        super().__init__()
        self.drop_first = drop_first
        self.truncate = truncate
        self.udp_received = 0
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", self.port))     # same port number as TCP
        self.udp.settimeout(0.1)
        self._udp_thread = threading.Thread(target=self._udp_loop, daemon=True)

    def start(self):
        super().start()
        self._udp_thread.start()
        return self

    def stop(self) -> None:
        super().stop()
        self._udp_thread.join(timeout=2)
        self.udp.close()

    def _udp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self.udp_received += 1
            if self.udp_received <= self.drop_first:
                continue                              # simulate a lost packet
            self.udp.sendto(answer_for(Message.from_bytes(data), self.truncate), addr)

    def _serve(self, conn) -> None:                  # TCP side: full answers
        query = Message.from_bytes(read_framed(conn))
        conn.sendall(frame_message(answer_for(query)))


class FakeDoTServer(_ThreadedServer):
    def __init__(self, cert: str, key: str) -> None:
        super().__init__()
        self._ctx = _server_tls_context(cert, key)
        self.queries = 0

    def _wrap(self, conn):
        return self._ctx.wrap_socket(conn, server_side=True)

    def _serve(self, conn) -> None:
        while True:                                   # many queries per connection
            query = Message.from_bytes(read_framed(conn))
            self.queries += 1
            conn.sendall(frame_message(answer_for(query)))


class FakeDoHServer(_ThreadedServer):
    """Real HTTP/2 over TLS (ALPN h2), implemented with the h2 library."""

    def __init__(self, cert: str, key: str, status: int = 200) -> None:
        super().__init__()
        self._ctx = _server_tls_context(cert, key, alpn=["h2"])
        self.status = status
        self.requests: list[dict] = []

    def _wrap(self, conn):
        return self._ctx.wrap_socket(conn, server_side=True)

    def _serve(self, conn) -> None:
        h2conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False))
        h2conn.initiate_connection()
        conn.sendall(h2conn.data_to_send())
        pending: dict[int, dict] = {}
        while True:
            data = conn.recv(65535)
            if not data:
                return
            for event in h2conn.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    headers = {k.decode(): v.decode() for k, v in event.headers}
                    pending[event.stream_id] = {"headers": headers, "body": b""}
                elif isinstance(event, h2.events.DataReceived):
                    pending[event.stream_id]["body"] += event.data
                    h2conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    req = pending.pop(event.stream_id)
                    self.requests.append(req)
                    if self.status != 200:
                        h2conn.send_headers(event.stream_id, [(":status", str(self.status))],
                                            end_stream=True)
                    else:
                        body = answer_for(Message.from_bytes(req["body"]))
                        h2conn.send_headers(event.stream_id, [
                            (":status", "200"),
                            ("content-type", "application/dns-message"),
                            ("content-length", str(len(body)))])
                        h2conn.send_data(event.stream_id, body, end_stream=True)
                elif isinstance(event, h2.events.ConnectionTerminated):
                    return
            conn.sendall(h2conn.data_to_send())
