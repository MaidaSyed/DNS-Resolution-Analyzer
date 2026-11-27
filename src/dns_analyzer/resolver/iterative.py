"""
iterative.py - Our own iterative DNS resolver (feature F2).

A recursive resolver (like 8.8.8.8) hides the work. Here WE do it:

    ask a ROOT server           -> "I don't know, ask the .test servers" (referral)
    ask a TLD server            -> "ask the example.test servers" (referral)
    ask the AUTHORITATIVE server-> the actual answer

All queries are sent with RD=0 (recursion NOT desired): we want referrals,
not a server doing the walk for us.

Terms used below:
  referral  : response with no answer but NS records in the AUTHORITY section.
  glue      : A records in the ADDITIONAL section giving the IP of those NS
              names, so we do not need another lookup (they would be circular
              for names inside the zone they serve).
  CNAME     : alias. We must restart the search for the alias target.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from dns_analyzer.dns import (Message, Rcode, ResourceRecord, RType, make_query,
                              normalize_name, rcode_to_text, type_to_text)

from .reliability import DnsTransport, QueryFailure

ROOT_ZONE = "."


@dataclass(frozen=True)
class NameServer:
    name: str | None
    ip: str


# Root hints: where resolution starts. In this project the "internet" is our
# private network, so the only root server is 10.10.3.10 (a real resolver
# would list a.root-servers.net ... m.root-servers.net here).
DEFAULT_ROOT_HINTS = [NameServer("a.root.", "10.10.3.10")]


def is_subdomain(child: str, parent: str) -> bool:
    """'www.example.test.' is a subdomain of 'test.' and of '.' (and of itself)."""
    child, parent = normalize_name(child), normalize_name(parent)
    return parent == "." or child == parent or child.endswith("." + parent)


@dataclass
class Hop:
    """One query sent to one server: a row of the trace."""
    step: int
    depth: int                 # >0 while resolving a nameserver's own address
    zone: str                  # zone whose servers we are asking
    server: NameServer
    port: int
    qname: str
    qtype: int
    outcome: str = "failed"    # referral | answer | cname | nodata | nxdomain | failed
    rtt_ms: float = 0.0
    attempts: int = 0
    used_tcp: bool = False
    rcode: int | None = None
    aa: bool = False
    detail: str = ""
    lines: list[str] = field(default_factory=list)   # records worth showing


@dataclass
class ResolutionResult:
    name: str
    qtype: int
    rcode: int | None = None
    answers: list[ResourceRecord] = field(default_factory=list)   # CNAME chain + final RRs
    hops: list[Hop] = field(default_factory=list)
    total_ms: float = 0.0
    error: str | None = None
    outcome: str = "failed"    # answer | nodata | nxdomain | failed

    @property
    def ok(self) -> bool:
        return self.error is None and self.outcome == "answer"

    @property
    def queries_sent(self) -> int:
        return len([h for h in self.hops if h.attempts])

    @property
    def retransmissions(self) -> int:
        return sum(max(h.attempts - 1, 0) for h in self.hops)


@dataclass
class _Walk:
    """Result of one root-to-answer walk for a single name."""
    kind: str                                   # answer | cname | nodata | nxdomain | failed
    records: list[ResourceRecord] = field(default_factory=list)
    rcode: int | None = None
    target: str | None = None                   # CNAME target to chase
    error: str | None = None


class IterativeResolver:
    def __init__(self, transport: DnsTransport | None = None,
                 root_hints: list[NameServer] | None = None,
                 max_referrals: int = 16, max_cnames: int = 8,
                 max_ns_depth: int = 3) -> None:
        self.transport = transport or DnsTransport()
        self.root_hints = list(root_hints or DEFAULT_ROOT_HINTS)
        self.max_referrals = max_referrals    # stops endless referral chains
        self.max_cnames = max_cnames          # stops CNAME loops
        self.max_ns_depth = max_ns_depth      # stops "need NS address -> need NS..." loops
        # What we have learned about servers (like a real resolver's "infra cache").
        self._rtt_ms: dict[str, float] = {}
        self._failures: dict[str, int] = {}

    # ------------------------------------------------------------------ API
    def resolve(self, name: str, qtype: int = RType.A) -> ResolutionResult:
        name = normalize_name(name)
        result = ResolutionResult(name=name, qtype=int(qtype))
        started = time.perf_counter()
        kind, records, rcode, error = self._resolve(name, int(qtype), 0, result.hops)
        result.total_ms = (time.perf_counter() - started) * 1000
        result.outcome, result.answers, result.error = kind, records, error
        result.rcode = rcode
        return result

    def clear_server_stats(self) -> None:
        self._rtt_ms.clear()
        self._failures.clear()

    # ------------------------------------------------------------ internals
    def _resolve(self, name: str, qtype: int, depth: int, hops: list[Hop]):
        """Resolve `name`, restarting at the root for every CNAME we meet."""
        chain: list[ResourceRecord] = []
        current, seen = name, {name}
        for _ in range(self.max_cnames + 1):
            walk = self._walk(current, qtype, depth, hops)
            chain += walk.records
            if walk.kind == "cname":
                if walk.target in seen:
                    return "failed", chain, None, f"CNAME loop at {walk.target}"
                seen.add(walk.target)
                current = walk.target
                continue
            return walk.kind, chain, walk.rcode, walk.error
        return "failed", chain, None, f"more than {self.max_cnames} CNAMEs in a row"

    def _walk(self, qname: str, qtype: int, depth: int, hops: list[Hop]) -> _Walk:
        zone = ROOT_ZONE
        servers = list(self.root_hints)
        for _ in range(self.max_referrals + 1):
            advanced = False
            for ns in self._order(servers):
                hop = Hop(step=len(hops) + 1, depth=depth, zone=zone, server=ns,
                          port=self.transport.port, qname=qname, qtype=qtype)
                hops.append(hop)
                query = make_query(qname, qtype, rd=False)    # RD=0: iterative
                try:
                    exchange = self.transport.exchange(ns.ip, query)
                except QueryFailure as exc:
                    hop.detail = str(exc)
                    self._record_failure(ns.ip)
                    continue                                   # failover: next server
                hop.attempts, hop.used_tcp = exchange.attempts, exchange.used_tcp
                hop.rtt_ms = exchange.rtt_ms
                self._record_success(ns.ip, exchange)
                response = exchange.response
                hop.rcode, hop.aa = response.rcode, response.flags.aa

                if response.rcode == Rcode.NXDOMAIN and response.flags.aa:
                    hop.outcome = "nxdomain"
                    hop.detail = "name does not exist"
                    return _Walk("nxdomain", rcode=Rcode.NXDOMAIN)
                if response.rcode != Rcode.NOERROR:
                    hop.detail = f"server returned {rcode_to_text(response.rcode)}"
                    self._record_failure(ns.ip)
                    continue

                chain, final, complete = self._follow_chain(response.answers, qname, qtype)
                if chain:
                    hop.lines = [str(rr) for rr in chain]
                    if complete:
                        hop.outcome = "answer"
                        hop.detail = "authoritative answer"
                        return _Walk("answer", chain, Rcode.NOERROR)
                    hop.outcome = "cname"
                    hop.detail = f"alias; restarting for {final}"
                    return _Walk("cname", chain, Rcode.NOERROR, target=final)

                referral = self._extract_referral(response, qname, zone)
                if referral:
                    new_zone, ns_names = referral
                    new_servers = self._servers_from_referral(
                        response, ns_names, depth, hops, hop)
                    if not new_servers:
                        hop.outcome = "failed"
                        hop.detail = f"referral to {new_zone} but no usable nameserver address"
                        self._record_failure(ns.ip)
                        continue
                    hop.outcome = "referral"
                    hop.detail = f"referral to {new_zone}"
                    zone, servers, advanced = new_zone, new_servers, True
                    break
                if response.flags.aa:
                    hop.outcome = "nodata"
                    hop.detail = "name exists but has no record of this type"
                    return _Walk("nodata", rcode=Rcode.NOERROR)
                hop.detail = "lame: no answer, no referral, not authoritative"
                self._record_failure(ns.ip)
            if not advanced:
                return _Walk("failed", error=f"all nameservers for zone '{zone}' failed")
        return _Walk("failed", error=f"more than {self.max_referrals} referrals")

    @staticmethod
    def _follow_chain(answers: list[ResourceRecord], name: str, qtype: int):
        """
        Walk CNAME records inside ONE answer section starting at `name`.
        Returns (records, last_name, complete). complete=True means records of
        the wanted type were found; False means the chain ends in a CNAME whose
        target is not answered here (we must look it up ourselves).
        """
        chain: list[ResourceRecord] = []
        current, visited = name, set()
        while True:
            direct = [rr for rr in answers if rr.name == current and rr.rtype == qtype]
            if direct:
                return chain + direct, current, True
            aliases = [rr for rr in answers if rr.name == current and rr.rtype == RType.CNAME]
            if not aliases or current in visited:
                return chain, current, False
            visited.add(current)
            chain.append(aliases[0])
            current = aliases[0].rdata

    @staticmethod
    def _extract_referral(response: Message, qname: str, zone: str):
        """
        Accept a referral only if the NS owner is (a) an ancestor of the name
        we asked for and (b) STRICTLY deeper than the zone we just asked. (b)
        guarantees progress, so a buggy or malicious server cannot send us in
        circles.
        """
        ns_rrs = [rr for rr in response.authorities
                  if rr.rtype == RType.NS and is_subdomain(qname, rr.name)
                  and rr.name != zone and is_subdomain(rr.name, zone)]
        if not ns_rrs:
            return None
        owner = ns_rrs[0].name
        return owner, [rr.rdata for rr in ns_rrs if rr.name == owner]

    def _servers_from_referral(self, response: Message, ns_names: list[str],
                               depth: int, hops: list[Hop], hop: Hop) -> list[NameServer]:
        """Turn NS names into IPs: use glue; if missing, resolve the name ourselves."""
        servers: list[NameServer] = []
        for ns_name in ns_names:
            # Only trust glue whose owner is one of the NS names we were given.
            glue = [rr.rdata for rr in response.additionals
                    if rr.rtype == RType.A and rr.name == ns_name]
            if glue:
                servers += [NameServer(ns_name, ip) for ip in glue]
                hop.lines.append(f"NS {ns_name} -> {', '.join(glue)} (glue)")
        if servers:
            return servers
        if depth >= self.max_ns_depth:
            return []
        for ns_name in ns_names:                       # no glue: look the NS up ourselves
            hop.lines.append(f"NS {ns_name} (no glue; resolving its address first)")
            kind, records, _rcode, _err = self._resolve(ns_name, RType.A, depth + 1, hops)
            if kind == "answer":
                servers += [NameServer(ns_name, rr.rdata) for rr in records
                            if rr.rtype == RType.A]
            if servers:
                break
        return servers

    # --- nameserver selection -------------------------------------------
    def _order(self, servers: list[NameServer]) -> list[NameServer]:
        """
        Try servers with fewer recent failures first, then the lowest measured
        RTT. Servers never measured count as 0 ms, so each gets tried once
        before we settle on the fastest. random() breaks ties, spreading load.
        """
        shuffled = random.sample(servers, len(servers))
        return sorted(shuffled, key=lambda s: (self._failures.get(s.ip, 0),
                                               self._rtt_ms.get(s.ip, 0.0)))

    def _record_success(self, ip: str, exchange) -> None:
        self._failures[ip] = 0
        # Karn's rule: a retransmitted query gives an ambiguous RTT (which send
        # did the reply answer?), so only clean first-try samples update the average.
        if exchange.attempts == 1:
            old = self._rtt_ms.get(ip)
            self._rtt_ms[ip] = exchange.rtt_ms if old is None else 0.7 * old + 0.3 * exchange.rtt_ms

    def _record_failure(self, ip: str) -> None:
        self._failures[ip] = self._failures.get(ip, 0) + 1


def zone_label(zone: str) -> str:
    if zone == ROOT_ZONE:
        return "ROOT"
    return "TLD" if zone.count(".") == 1 else "AUTH"


def _shorten(text: str, limit: int = 110) -> str:
    """Keep trace lines readable (a TXT record can be over 1500 characters)."""
    return text if len(text) <= limit else text[:limit - 1] + "…"


def format_trace(result: ResolutionResult) -> str:
    """Human-readable hop-by-hop trace (what the viva examiner will look at)."""
    out = [f";; Iterative resolution of {result.name} {type_to_text(result.qtype)}",
           ";; Every query below was sent with RD=0 (we do the recursion ourselves)", ""]
    for hop in result.hops:
        indent = "    " * hop.depth
        out.append(f"{indent}[{hop.step:>2}] {zone_label(hop.zone):<4} zone '{hop.zone}'  "
                   f"ask {hop.server.name or '?'} ({hop.server.ip}:{hop.port})  "
                   f"{hop.qname} {type_to_text(hop.qtype)}")
        if hop.attempts:
            extra = []
            if hop.attempts > 1:
                extra.append(f"{hop.attempts - 1} retransmission(s)")
            if hop.used_tcp:
                extra.append("TC bit set -> retried over TCP")
            flags = f"rcode={rcode_to_text(hop.rcode)}{' aa' if hop.aa else ''}"
            out.append(f"{indent}     -> {hop.outcome.upper()}: {hop.detail}  "
                       f"[{flags}, rtt {hop.rtt_ms:.2f} ms"
                       f"{', ' + ', '.join(extra) if extra else ''}]")
        else:
            out.append(f"{indent}     -> FAILED: {hop.detail}  (trying next server)")
        for line in hop.lines:
            out.append(f"{indent}        {_shorten(line)}")
    out.append("")
    if result.ok:
        out.append(";; ANSWER")
        out += [_shorten(str(rr)) for rr in result.answers]
    elif result.error:
        out.append(f";; FAILED: {result.error}")
    elif result.outcome == "nxdomain":
        out.append(";; NXDOMAIN: the name does not exist")
    else:
        out.append(";; NODATA: the name exists but has no record of the requested type")
    out.append(f";; {result.queries_sent} queries, {result.retransmissions} retransmissions, "
               f"{result.total_ms:.1f} ms total")
    return "\n".join(out)
