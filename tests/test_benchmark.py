"""
Tests for the statistics (metrics.py), the benchmark runner (F7) and the graphs.
The runner is tested against local fake servers, so no root or lab is needed.
Run:  pytest tests/test_benchmark.py -v
"""
import math
import shutil

import pandas as pd
import pytest

from dns_analyzer.benchmark import metrics
from dns_analyzer.benchmark.capture import CaptureSummary
from dns_analyzer.benchmark.runner import (ALL_METHODS, BenchmarkConfig, BenchmarkRunner,
                                           Endpoints, NullLab, benchmark_names, cache_modes,
                                           generate_report)
from fake_hierarchy import ROOT_IP, Hierarchy
from fake_servers import FakeDo53Server, FakeDoHServer, FakeDoTServer, make_self_signed_cert


# ------------------------------------------------------------- statistics --
def test_percentile_and_latency_stats():
    values = list(range(1, 101))                       # 1..100
    assert metrics.percentile(values, 95) == pytest.approx(95.05)
    stats = metrics.latency_stats(values)
    assert stats["mean"] == 50.5 and stats["median"] == 50.5
    assert stats["std"] == pytest.approx(29.011, abs=1e-3)
    assert math.isnan(metrics.latency_stats([])["mean"])
    assert metrics.latency_stats([7])["std"] == 0.0     # one value: no spread


def test_summarize_series_uses_only_successes_for_latency():
    q = pd.DataFrame({"ok": [True, True, False, True], "query_ms": [10.0, 20.0, 5000.0, 30.0],
                      "app_retrans": [0, 1, 2, 0]})
    cap = CaptureSummary(packets=40, bytes=4000, tcp_connections=2,
                         tcp_handshake_ms=[10.0, 20.0], tls_handshake_ms=[30.0])
    row = metrics.summarize_series(q, cap)
    assert row["success_rate"] == 75.0 and row["mean_ms"] == 20.0 and row["median_ms"] == 20.0
    assert row["app_retransmissions"] == 3 and row["retrans_per_query"] == 0.75
    assert row["packets_per_query"] == 10 and row["bytes_per_query"] == 1000
    assert row["tcp_handshake_ms"] == 15.0 and row["tls_handshake_ms"] == 30.0
    assert row["first_query_ms"] == 10.0 and row["later_query_ms"] == 25.0


def test_summarize_series_without_capture_leaves_nan():
    q = pd.DataFrame({"ok": [True], "query_ms": [5.0], "app_retrans": [0]})
    row = metrics.summarize_series(q, None)
    assert math.isnan(row["packets_per_query"]) and row["mean_ms"] == 5.0


def test_aggregate_runs_mean_and_std_over_runs():
    base = {"condition": "good", "rtt_ms": 20, "loss_pct": 0, "method": "do53", "cache": "cold"}
    runs = pd.DataFrame([{**base, "run": r, "mean_ms": m, "median_ms": m, "p95_ms": m * 2,
                          "success_rate": 100.0, "packets_per_query": 2.0, "bytes_per_query": 200.0,
                          "retrans_per_query": 0.0, "first_query_ms": m, "later_query_ms": m,
                          "tcp_handshake_ms": math.nan, "tls_handshake_ms": math.nan}
                         for r, m in ((1, 10.0), (2, 20.0), (3, 30.0))])
    out = metrics.aggregate_runs(runs)
    assert len(out) == 1 and out.loc[0, "runs"] == 3
    assert out.loc[0, "mean_ms_mean"] == 20.0 and out.loc[0, "mean_ms_std"] == pytest.approx(10.0)
    table = metrics.summary_table(out)
    assert table.loc[0, "mean ms"] == "20.0 ± 10.0"
    assert "| condition | method |" in metrics.to_markdown(table)


def test_names_and_cache_modes():
    assert benchmark_names(3) == ["host001.example.test", "host002.example.test", "host003.example.test"]
    with pytest.raises(ValueError):
        benchmark_names(101)
    assert cache_modes("iterative") == ["cold"] and cache_modes("dot_reused") == ["cold", "warm"]


# ---------------------------------------------------------- runner end-to-end --
@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not installed")
    return make_self_signed_cert(tmp_path_factory.mktemp("benchcerts"))


def test_full_benchmark_on_fake_servers(tmp_path, cert):
    names = ["www.example.test", "alias.example.test"]
    with Hierarchy() as h, FakeDo53Server() as do53, FakeDoTServer(*cert) as dot, FakeDoHServer(*cert) as doh:
        endpoints = Endpoints(root_ip=ROOT_IP, dns_port=h.port, resolver_ip="127.0.0.1",
                              resolver_port=do53.port, dot_port=dot.port,
                              doh_url=f"https://127.0.0.1:{doh.port}/dns-query", cafile=cert[0])
        cfg = BenchmarkConfig(conditions=["good", "poor"], runs=2, names=names, out_dir=tmp_path,
                              capture_dir=tmp_path / "caps", capture=False, udp_timeout=0.5,
                              endpoints=endpoints)
        messages = []
        result = BenchmarkRunner(cfg, NullLab(), log=messages.append).run()

    series_per_run = sum(len(cache_modes(m)) for m in ALL_METHODS)          # 1 + 2*5 = 11
    assert len(result.runs) == 2 * 2 * series_per_run
    assert len(result.queries) == len(result.runs) * len(names)
    assert result.queries["ok"].all()
    assert set(result.queries["method"]) == set(ALL_METHODS)
    assert any("netem is OFF" in m for m in messages)                       # honest labelling
    assert not result.queries["netem"].any()
    # connection reuse is visible in the data
    dot_fresh = result.queries[(result.queries.method == "dot_fresh")]
    dot_reused = result.queries[(result.queries.method == "dot_reused")]
    assert not dot_fresh["reused"].any() and dot_reused["reused"].sum() == len(dot_reused) - 4 * 2  # first of each series is new
    # files
    for name in ("benchmark_queries.csv", "benchmark_runs.csv", "benchmark_summary.csv", "benchmark_summary.md"):
        assert (tmp_path / name).exists(), name
    assert len(result.summary) == 2 * series_per_run                        # one row per condition x series
    graph_files = {p.name for p in (tmp_path / "graphs").glob("*.png")}
    assert {"latency_cold.png", "latency_warm.png", "success_rate.png", "connection_reuse.png",
            "latency_cdf_good.png", "latency_cdf_poor.png"} <= graph_files


def test_runner_rejects_unknown_method(tmp_path):
    with pytest.raises(ValueError):
        BenchmarkRunner(BenchmarkConfig(methods=["carrier_pigeon"], out_dir=tmp_path))


def test_failed_queries_lower_success_rate(tmp_path):
    with Hierarchy(auth_kwargs={"mode": "dead"}) as h:
        cfg = BenchmarkConfig(conditions=["good"], runs=1, names=["www.example.test"], methods=["iterative"],
                              out_dir=tmp_path, capture=False, udp_timeout=0.05, udp_attempts=2,
                              endpoints=Endpoints(root_ip=ROOT_IP, dns_port=h.port))
        result = BenchmarkRunner(cfg, NullLab(), log=lambda m: None).run()
    assert result.runs.loc[0, "success_rate"] == 0.0
    assert not result.queries.loc[0, "ok"] and result.queries.loc[0, "error"]


def test_generate_report_can_be_rerun_from_csv(tmp_path, cert):
    with Hierarchy() as h:
        cfg = BenchmarkConfig(conditions=["good"], runs=1, names=["www.example.test"], methods=["iterative"],
                              out_dir=tmp_path, capture=False,
                              endpoints=Endpoints(root_ip=ROOT_IP, dns_port=h.port))
        BenchmarkRunner(cfg, NullLab(), log=lambda m: None).run()
    for png in (tmp_path / "graphs").glob("*.png"):
        png.unlink()
    result = generate_report(tmp_path, log=lambda m: None)
    assert len(result.summary) == 1 and list((tmp_path / "graphs").glob("*.png"))
