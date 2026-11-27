"""
runner.py - Automated benchmark (feature F7).

For every network condition (good / moderate / poor) and every run (default 3)
the runner measures all methods:

    iterative   our own resolver talking to root -> TLD -> authoritative
    do53        UDP stub query to the recursive resolver
    dot_fresh   DoT, a NEW TCP+TLS connection for every query
    dot_reused  DoT, ONE connection reused for all queries
    doh_fresh / doh_reused   the same for DoH (HTTP/2)

Cache modes (resolver-based methods only; our iterative resolver has no cache):
    cold   resolver cache flushed before EVERY query (full root->TLD->auth walk)
    warm   all names resolved once beforehand, then measured (cache hits)

Each series is recorded with tcpdump so packets, bytes (handshakes included)
and retransmissions come from the real capture.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from dns_analyzer.lab import CERT_DIR, CONDITIONS
from dns_analyzer.clients import Do53Client, DoHClient, DoTClient, QueryResult
from dns_analyzer.resolver import DnsTransport, IterativeResolver, NameServer

from . import graphs, metrics
from .capture import analyze_pcap

ALL_METHODS = ["iterative", "do53", "dot_fresh", "dot_reused", "doh_fresh", "doh_reused"]
CONDITION_ORDER = ["good", "moderate", "poor"]


def benchmark_names(count: int) -> list[str]:
    """host001.example.test ... (the zone file defines host001 .. host100)."""
    if not 1 <= count <= 100:
        raise ValueError("the example.test zone has 100 benchmark names (1..100)")
    return [f"host{i:03d}.example.test" for i in range(1, count + 1)]


@dataclass
class Endpoints:
    root_ip: str = "10.10.3.10"
    dns_port: int = 53                   # port of root/TLD/authoritative servers
    resolver_ip: str = "10.10.2.53"
    resolver_port: int = 53
    dot_port: int = 853
    doh_url: str = "https://10.10.2.53/dns-query"
    cafile: str | None = str(CERT_DIR / "ca.crt")


@dataclass
class BenchmarkConfig:
    conditions: list[str] = field(default_factory=lambda: list(CONDITION_ORDER))
    runs: int = 3
    names: list[str] = field(default_factory=lambda: benchmark_names(100))
    methods: list[str] = field(default_factory=lambda: list(ALL_METHODS))
    out_dir: Path = Path("results")
    capture_dir: Path = Path("captures")
    capture: bool = True
    keep_pcaps: bool = True
    udp_timeout: float = 1.0             # first wait for UDP methods (doubles each retry)
    udp_attempts: int = 3
    tcp_timeout: float = 5.0             # DoT / DoH socket timeout
    endpoints: Endpoints = field(default_factory=Endpoints)


# ------------------------------------------------------------- lab control --
class NullLab:
    """Does nothing; used when the servers already run somewhere (and in tests)."""
    applies_conditions = False           # True only if delay/loss is really applied
    def apply_condition(self, key: str) -> None: ...
    def clear_condition(self) -> None: ...
    def flush_cache(self) -> None: ...
    def prime_cache(self, names: list[str]) -> None: ...

    @contextmanager
    def capture(self, path: Path):
        yield None


class RealLab(NullLab):
    """Controls the namespace testbed from lab.py (needs root)."""
    def __init__(self, netem: bool = True) -> None:
        from dns_analyzer import lab
        self._lab, self._netem = lab, netem
        self.applies_conditions = netem

    def apply_condition(self, key: str) -> None:
        if self._netem:
            self._lab.set_condition(self._lab.CONDITIONS[key])

    def clear_condition(self) -> None:
        if self._netem:
            self._lab.clear_condition()

    def flush_cache(self) -> None:
        self._lab.flush_resolver_cache()

    def prime_cache(self, names: list[str]) -> None:
        self._lab.prime_resolver_cache(names)

    @contextmanager
    def capture(self, path: Path):
        cap = self._lab.Capture(path).start()
        try:
            yield cap
        finally:
            cap.stop()


# ---------------------------------------------------------------- queriers --
def _row_from_result(result: QueryResult) -> dict:
    return {"ok": result.ok, "query_ms": result.query_time_ms, "error": result.error or "",
            "app_retrans": result.retransmissions, "reused": result.reused_connection,
            "handshake_ms": result.handshake_ms, "rcode": result.rcode if result.rcode is not None else -1}


class _IterativeQuerier:
    def __init__(self, cfg: BenchmarkConfig) -> None:
        ep = cfg.endpoints
        transport = DnsTransport(port=ep.dns_port, timeout=cfg.udp_timeout, attempts=cfg.udp_attempts)
        self.resolver = IterativeResolver(transport, [NameServer("root", ep.root_ip)])

    def query(self, name: str) -> dict:
        self.resolver.clear_server_stats()
        r = self.resolver.resolve(name)
        return {"ok": r.ok, "query_ms": r.total_ms, "error": r.error or ("" if r.ok else r.outcome),
                "app_retrans": r.retransmissions, "reused": False, "handshake_ms": 0.0,
                "rcode": r.rcode if r.rcode is not None else -1}

    def close(self) -> None: ...


class _Do53Querier:
    def __init__(self, cfg: BenchmarkConfig) -> None:
        ep = cfg.endpoints
        self.client = Do53Client(ep.resolver_ip, ep.resolver_port, timeout=cfg.udp_timeout,
                                 attempts=cfg.udp_attempts)

    def query(self, name: str) -> dict:
        return _row_from_result(self.client.query(name))

    def close(self) -> None: ...


class _SecureQuerier:
    """DoT or DoH; reuse=True keeps one connection, reuse=False opens a new one per query."""
    def __init__(self, cfg: BenchmarkConfig, kind: str, reuse: bool) -> None:
        self.cfg, self.kind, self.reuse = cfg, kind, reuse
        self.client = self._new_client() if reuse else None

    def _new_client(self):
        ep = self.cfg.endpoints
        if self.kind == "dot":
            return DoTClient(ep.resolver_ip, ep.dot_port, cafile=ep.cafile, timeout=self.cfg.tcp_timeout)
        return DoHClient(ep.doh_url, cafile=ep.cafile, timeout=self.cfg.tcp_timeout)

    def query(self, name: str) -> dict:
        if self.reuse:
            return _row_from_result(self.client.query(name))
        client = self._new_client()
        try:
            return _row_from_result(client.query(name))
        finally:
            client.close()

    def close(self) -> None:
        if self.client:
            self.client.close()


def make_querier(method: str, cfg: BenchmarkConfig):
    if method == "iterative":
        return _IterativeQuerier(cfg)
    if method == "do53":
        return _Do53Querier(cfg)
    kind, mode = method.split("_")
    return _SecureQuerier(cfg, kind, reuse=(mode == "reused"))


def cache_modes(method: str) -> list[str]:
    return ["cold"] if method == "iterative" else ["cold", "warm"]


# ------------------------------------------------------------------ runner --
@dataclass
class BenchmarkResult:
    queries: pd.DataFrame
    runs: pd.DataFrame
    summary: pd.DataFrame


class BenchmarkRunner:
    def __init__(self, config: BenchmarkConfig, lab: NullLab | None = None, log=print) -> None:
        unknown = [m for m in config.methods if m not in ALL_METHODS]
        if unknown:
            raise ValueError(f"unknown method(s): {unknown}; choose from {ALL_METHODS}")
        self.cfg, self.lab, self.log = config, lab or NullLab(), log
        self._query_rows: list[dict] = []
        self._run_rows: list[dict] = []

    def run(self) -> BenchmarkResult:
        cfg = self.cfg
        cfg.out_dir.mkdir(parents=True, exist_ok=True)
        started = time.time()
        try:
            for cond_key in cfg.conditions:
                cond = CONDITIONS[cond_key]
                self.log(f"\n=== condition {cond.label}: RTT {cond.rtt_ms:g} ms, loss {cond.loss_pct:g}% ===")
                if not self.lab.applies_conditions:
                    self.log("  NOTE: netem is OFF - this RTT/loss is only a label, NOT applied to the network")
                self.lab.apply_condition(cond_key)
                time.sleep(0.3)
                for run in range(1, cfg.runs + 1):
                    for method in cfg.methods:
                        for cache in cache_modes(method):
                            self._series(cond, run, method, cache)
                self._write_csvs()                    # checkpoint after every condition
        finally:
            self.lab.clear_condition()
        result = self.finish()
        self.log(f"\nbenchmark finished in {(time.time() - started) / 60:.1f} min; "
                 f"results in {cfg.out_dir}/")
        return result

    def _series(self, cond, run: int, method: str, cache: str) -> None:
        cfg = self.cfg
        names = cfg.names
        pcap = cfg.capture_dir / f"{cond.key}_run{run}_{method}_{cache}.pcap"
        querier = make_querier(method, cfg)
        rows: list[dict] = []
        try:
            if cache == "warm":
                self.lab.flush_cache()
                self.lab.prime_cache(names)
            capture_path = pcap if cfg.capture else None
            with self.lab.capture(capture_path) if capture_path else _nothing():
                for index, name in enumerate(names):
                    if cache == "cold" and method != "iterative":
                        self.lab.flush_cache()
                    row = querier.query(name)
                    row.update({"condition": cond.key, "rtt_ms": cond.rtt_ms, "loss_pct": cond.loss_pct,
                                "netem": self.lab.applies_conditions,
                                "run": run, "method": method, "cache": cache, "index": index, "name": name})
                    rows.append(row)
        finally:
            querier.close()
        frame = pd.DataFrame(rows)
        capture_summary = None
        if cfg.capture and pcap.exists() and pcap.stat().st_size > 24:
            capture_summary = analyze_pcap(pcap)
            if not cfg.keep_pcaps:
                pcap.unlink()
        run_row = {"condition": cond.key, "rtt_ms": cond.rtt_ms, "loss_pct": cond.loss_pct,
                   "netem": self.lab.applies_conditions, "run": run, "method": method, "cache": cache,
                   **metrics.summarize_series(frame, capture_summary)}
        self._query_rows += rows
        self._run_rows.append(run_row)
        self.log(f"  [{cond.key} run {run}/{cfg.runs}] {method:<10} {cache:<4} "
                 f"mean {run_row['mean_ms']:8.1f} ms  p95 {run_row['p95_ms']:8.1f} ms  "
                 f"ok {run_row['success_rate']:5.1f}%  retrans {run_row['app_retransmissions']}")

    def _write_csvs(self) -> None:
        out = self.cfg.out_dir
        pd.DataFrame(self._query_rows).to_csv(out / "benchmark_queries.csv", index=False)
        pd.DataFrame(self._run_rows).to_csv(out / "benchmark_runs.csv", index=False)

    def finish(self) -> BenchmarkResult:
        self._write_csvs()
        return generate_report(self.cfg.out_dir, log=self.log)


@contextmanager
def _nothing():
    yield None


# ------------------------------------------------------------------ report --
def generate_report(out_dir: str | Path, log=print) -> BenchmarkResult:
    """Read the CSVs, write the summary table (CSV + markdown) and draw all graphs."""
    out = Path(out_dir)
    queries = pd.read_csv(out / "benchmark_queries.csv")
    runs = pd.read_csv(out / "benchmark_runs.csv")
    queries["ok"] = queries["ok"].astype(bool)
    summary = metrics.aggregate_runs(runs)
    summary.to_csv(out / "benchmark_summary.csv", index=False)
    table = metrics.summary_table(summary)
    (out / "benchmark_summary.md").write_text(metrics.to_markdown(table) + "\n")
    files = graphs.draw_all(summary, queries, out / "graphs")
    log(f"summary table: {out / 'benchmark_summary.md'}")
    log(f"{len(files)} graphs written to {out / 'graphs'}/")
    return BenchmarkResult(queries, runs, summary)
