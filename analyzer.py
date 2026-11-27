#!/usr/bin/env python3
"""
analyzer.py - Command-line entry point of the DNS Resolution Analyzer.

Resolve a name (run these through the lab with --lab, using sudo):
  sudo .venv/bin/python analyzer.py iterative www.example.test --lab
  sudo .venv/bin/python analyzer.py do53 www.example.test --lab
  sudo .venv/bin/python analyzer.py dot  www.example.test --lab --repeat 3
  sudo .venv/bin/python analyzer.py doh  www.example.test --lab --repeat 3

Control the testbed:
  sudo .venv/bin/python analyzer.py lab up | down | status
  sudo .venv/bin/python analyzer.py lab netem good|moderate|poor|clear

Measure and analyse:
  sudo .venv/bin/python analyzer.py benchmark            (3 conditions x 3 runs x all methods)
  sudo .venv/bin/python analyzer.py benchmark --quick    (small and fast, for a first try)
  python analyzer.py analyze captures/some.pcap          (packet capture analysis)
  python analyzer.py report                              (rebuild tables and graphs from the CSVs)

Without --lab the commands talk to the addresses you give (--server, --url, --root),
so they also work against public resolvers, e.g.
  python analyzer.py dot www.example.com --server 1.1.1.1 --hostname one.one.one.one
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from dns_analyzer import lab as labmod  # noqa: E402
from dns_analyzer.benchmark.capture import analyze_pcap, format_summary  # noqa: E402
from dns_analyzer.clients import Do53Client, DoHClient, DoTClient, QueryResult  # noqa: E402
from dns_analyzer.dns import rcode_to_text, text_to_type  # noqa: E402
from dns_analyzer.resolver import (DnsTransport, IterativeResolver, NameServer,  # noqa: E402
                                   format_trace)

DEFAULT_RESOLVER = "10.10.2.53"


def print_result(index: int, result: QueryResult) -> None:
    print(f"\n[{result.method.upper()}] query #{index}")
    if not result.ok:
        print(f"  FAILED: {result.error}  (after {result.query_time_ms:.1f} ms)")
        return
    print(f"  rcode: {rcode_to_text(result.rcode)}")
    for line in result.summary_answers():
        print(f"  answer: {line[:150] + '...' if len(line) > 150 else line}")
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
    parser = argparse.ArgumentParser(description="DNS Resolution Analyzer",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("name", help="domain name to resolve, e.g. www.example.test")
        p.add_argument("--type", default="A", help="record type (default A)")
        p.add_argument("--repeat", type=int, default=1,
                       help="send the query N times (shows connection reuse)")
        p.add_argument("--lab", action="store_true",
                       help="run inside the lab's client namespace (needs sudo and 'lab up')")

    p = sub.add_parser("iterative", help="our own iterative resolver (root -> TLD -> authoritative)")
    common(p)
    p.add_argument("--root", default=labmod.ROOT_IP, help="root server IP (root hints)")
    p.add_argument("--port", type=int, default=53, help="UDP/TCP port of the DNS servers")
    p.add_argument("--timeout", type=float, default=1.0, help="first retransmission timeout (s)")
    p.add_argument("--attempts", type=int, default=3, help="UDP sends per query")

    p = sub.add_parser("do53", help="plain DNS over UDP/53 via a recursive resolver")
    common(p)
    p.add_argument("--server", default=DEFAULT_RESOLVER)
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--timeout", type=float, default=1.0)

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

    p = sub.add_parser("lab", help="build / inspect / stop the virtual testbed (needs sudo)")
    p.add_argument("action", choices=["up", "down", "status", "netem", "flush"])
    p.add_argument("condition", nargs="?", choices=["good", "moderate", "poor", "clear"],
                   help="for 'netem': which network condition to apply")

    p = sub.add_parser("benchmark", help="run all methods under the 3 network conditions (needs sudo)")
    p.add_argument("--conditions", default="good,moderate,poor", help="comma separated")
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--names", type=int, default=100, help="names per run (1..100)")
    p.add_argument("--methods", default="all",
                   help="comma separated: iterative,do53,dot_fresh,dot_reused,doh_fresh,doh_reused")
    p.add_argument("--quick", action="store_true", help="20 names, 1 run (fast try-out)")
    p.add_argument("--no-netem", action="store_true", help="do NOT apply delay/loss (numbers are then not valid)")
    p.add_argument("--no-capture", action="store_true", help="skip tcpdump (no packet/byte columns)")
    p.add_argument("--no-keep-pcaps", action="store_true", help="delete pcap files after analysis")
    p.add_argument("--out", default="results")
    p.add_argument("--captures", default="captures")

    p = sub.add_parser("analyze", help="analyse a tcpdump .pcap file (packets, bytes, handshakes, retransmissions)")
    p.add_argument("pcap")
    p.add_argument("--client-ip", default="10.10.1.10")
    p.add_argument("--queries", type=int, help="number of queries in the capture (for per-query figures)")

    p = sub.add_parser("report", help="rebuild the summary table and graphs from results/*.csv")
    p.add_argument("--out", default="results")
    return parser


def hand_back_ownership(*paths: str) -> None:
    """When run with sudo, give the new files back to the normal user."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    for top in paths:
        for root, dirs, files in os.walk(top):
            for name in [root, *[os.path.join(root, n) for n in dirs + files]]:
                try:
                    os.chown(name, int(uid), int(gid))
                except OSError:
                    pass


def run_lab_command(args) -> int:
    if args.action == "up":
        labmod.up()
    elif args.action == "down":
        labmod.down()
    elif args.action == "status":
        print(labmod.status())
    elif args.action == "flush":
        labmod.require_root()
        labmod.flush_resolver_cache()
        print("resolver cache flushed")
    else:
        if not args.condition:
            print("usage: analyzer.py lab netem good|moderate|poor|clear", file=sys.stderr)
            return 2
        if args.condition == "clear":
            labmod.clear_condition()
            print("client link: no delay, no loss")
        else:
            cond = labmod.CONDITIONS[args.condition]
            labmod.set_condition(cond)
            print(f"client link: {cond.label}: RTT {cond.rtt_ms:g} ms, loss {cond.loss_pct:g}% (each direction)")
    return 0


def run_benchmark(args) -> int:
    from dns_analyzer.benchmark.runner import (ALL_METHODS, BenchmarkConfig, BenchmarkRunner,
                                               RealLab, benchmark_names)
    labmod.require_root()
    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    bad = [c for c in conditions if c not in labmod.CONDITIONS]
    if bad:
        print(f"error: unknown condition(s) {bad}; choose from {list(labmod.CONDITIONS)}", file=sys.stderr)
        return 2
    methods = ALL_METHODS if args.methods == "all" else [m.strip() for m in args.methods.split(",")]
    names, runs = (20, 1) if args.quick else (args.names, args.runs)
    config = BenchmarkConfig(conditions=conditions, runs=runs, names=benchmark_names(names),
                             methods=methods, out_dir=pathlib.Path(args.out),
                             capture_dir=pathlib.Path(args.captures), capture=not args.no_capture,
                             keep_pcaps=not args.no_keep_pcaps)
    labmod.enter_client_namespace()
    try:
        BenchmarkRunner(config, RealLab(netem=not args.no_netem)).run()
    finally:
        hand_back_ownership(args.out, args.captures)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.mode == "lab":
            return run_lab_command(args)
        if args.mode == "benchmark":
            return run_benchmark(args)
        if args.mode == "analyze":
            print(format_summary(analyze_pcap(args.pcap, args.client_ip), args.queries))
            return 0
        if args.mode == "report":
            from dns_analyzer.benchmark.runner import generate_report
            generate_report(args.out)
            hand_back_ownership(args.out)
            return 0
    except (labmod.LabError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        qtype = text_to_type(args.type)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.lab:
        try:
            labmod.enter_client_namespace()
        except labmod.LabError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if args.mode in ("dot", "doh") and not args.cafile and not args.insecure:
            ca = labmod.CERT_DIR / "ca.crt"
            if ca.exists():
                args.cafile = str(ca)

    if args.mode == "iterative":
        transport = DnsTransport(port=args.port, timeout=args.timeout, attempts=args.attempts)
        resolver = IterativeResolver(transport, [NameServer("root-hint", args.root)])
        failures = 0
        for _ in range(args.repeat):
            result = resolver.resolve(args.name, qtype)
            print(format_trace(result))
            failures += 0 if result.ok else 1
        return 1 if failures else 0

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
