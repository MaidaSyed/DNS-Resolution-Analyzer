#!/usr/bin/env python3
"""
Send ONE query built by our own codec to a DNS server and print the decoded
reply. Use it to compare against `dig` (viva-friendly proof that F1 works).

  python scripts/codec_smoke.py www.example.com --server 8.8.8.8 --rd
  python scripts/codec_smoke.py www.example.test --server 10.10.3.10   (later)
"""
import argparse
import pathlib
import socket
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from dns_analyzer.dns import DNSError, Message, make_query, text_to_type  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name")
    ap.add_argument("--server", default="127.0.0.53")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--type", default="A")
    ap.add_argument("--rd", action="store_true", help="ask for recursion")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    query = make_query(args.name, text_to_type(args.type), rd=args.rd)
    wire = query.to_bytes()
    print(f";; sending {len(wire)} bytes to {args.server}:{args.port}")
    print(f";; hex: {wire.hex()}")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.sendto(wire, (args.server, args.port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            print(";; timeout: no reply")
            return 1
    print(f";; received {len(data)} bytes\n")
    try:
        reply = Message.from_bytes(data)
    except DNSError as exc:
        print(f";; could not decode reply: {exc}")
        return 2
    if reply.id != query.id:
        print(";; WARNING: reply ID does not match query ID")
    print(reply.to_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
