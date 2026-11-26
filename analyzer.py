#!/usr/bin/env python3
"""
analyzer.py - Command-line entry point of the DNS Resolution Analyzer.

  python analyzer.py do53 www.example.test
  python analyzer.py dot  www.example.test --repeat 3
  python analyzer.py doh  www.example.test --repeat 3

(`iterative` and `benchmark` are added in later batches.)
Defaults point at the project's recursive resolver (10.10.2.53). For a quick
check against a public resolver use e.g.:
  python analyzer.py dot www.example.com --server 1.1.1.1 --hostname one.one.one.one
  python analyzer.py doh www.example.com --url https://cloudflare-dns.com/dns-query
"""
from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from dns_analyzer.clients import Do53Client, DoHClient, DoTClient, QueryResult  # noqa: E402
from dns_analyzer.dns import rcode_to_text, text_to_type  # noqa: E402

DEFAULT_RESOLVER = "10.10.2.53"


def print_result(index: int, result: QueryResult) -> None:
    print(f"\n[{result.method.upper()}] query #{index}")
    if not result.ok:
        print(f"  FAILED: {result.error}  (after {result.query_time_ms:.1f} ms)")
        return
    print(f"  rcode: {rcode_to_text(result.rcode)}")
    for line in result.summary_answers():
        print(f"  answer: {line}")
    print(f"  total time:      {result.query_time_ms:8.2f} ms")
    if result.method == "dot" and not result.reused_connection:
        print(f"    TCP connect:   {result.connect_ms:8.2f} ms")
        print(f"    TLS handshake: {result.tls_ms:8.2f} ms")
    if result.method != "do53":
        print(f"  connection reused: {result.reused_connection}")
    if result.method == "do53":
        print(f"  UDP sends: {result.attempts} (retransmissions: {result.retransmissions})"
              f"{'  [TCP fallback used]' if result.used_tcp_fallback else ''}")
    print(f"  DNS bytes sent/received: {result.bytes_sent}/{result.bytes_received}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DNS Resolution Analyzer")
    sub = parser.add_subparsers(dest="mode", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("name", help="domain name to resolve, e.g. www.example.test")
        p.add_argument("--type", default="A", help="record type (default A)")
        p.add_argument("--repeat", type=int, default=1,
                       help="send the query N times (shows connection reuse)")

    p = sub.add_parser("do53", help="plain DNS over UDP/53 via a recursive resolver")
    common(p)
    p.add_argument("--server", default=DEFAULT_RESOLVER)
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--timeout", type=float, default=2.0)

    p = sub.add_parser("dot", help="DNS over TLS (TCP 853, TLS 1.3)")
    common(p)
    p.add_argument("--server", default=DEFAULT_RESOLVER)
    p.add_argument("--port", type=int, default=853)
    p.add_argument("--hostname", help="name to verify in the certificate (default: server)")
    p.add_argument("--cafile", help="CA certificate (PEM) that signed the server cert")
    p.add_argument("--insecure", action="store_true", help="skip certificate verification")

    p = sub.add_parser("doh", help="DNS over HTTPS (HTTP/2 POST, port 443)")
    common(p)
    p.add_argument("--url", default=f"https://{DEFAULT_RESOLVER}/dns-query")
    p.add_argument("--hostname", help="SNI / certificate name if the URL uses an IP")
    p.add_argument("--cafile", help="CA certificate (PEM) that signed the server cert")
    p.add_argument("--insecure", action="store_true", help="skip certificate verification")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        qtype = text_to_type(args.type)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.mode == "do53":
        client = Do53Client(args.server, args.port, timeout=args.timeout)
    elif args.mode == "dot":
        client = DoTClient(args.server, args.port, server_hostname=args.hostname,
                           cafile=args.cafile, insecure=args.insecure)
    else:
        client = DoHClient(args.url, cafile=args.cafile, insecure=args.insecure,
                           sni_hostname=args.hostname)

    failures = 0
    try:
        for i in range(1, args.repeat + 1):
            result = client.query(args.name, qtype)
            print_result(i, result)
            failures += 0 if result.ok else 1
    finally:
        if hasattr(client, "close"):
            client.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())