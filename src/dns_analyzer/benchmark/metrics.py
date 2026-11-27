"""
metrics.py - Statistics for the benchmark (mean, median, 95th percentile,
mean +- standard deviation over runs, success rate, per-query packet/byte cost).
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .capture import CaptureSummary

# Columns that identify one data series in the summary tables.
GROUP = ["condition", "rtt_ms", "loss_pct", "method", "cache"]
# Per-run measurements that get averaged over the runs (mean and std).
RUN_METRICS = ["mean_ms", "median_ms", "p95_ms", "success_rate", "packets_per_query",
               "bytes_per_query", "retrans_per_query", "first_query_ms", "later_query_ms",
               "tcp_handshake_ms", "tls_handshake_ms"]


def percentile(values, q: float) -> float:
    """q-th percentile with linear interpolation (like numpy / Excel PERCENTILE.INC)."""
    values = [v for v in values if v is not None and not math.isnan(v)]
    return float(np.percentile(values, q)) if values else math.nan


def latency_stats(values) -> dict[str, float]:
    values = [v for v in values if v is not None and not math.isnan(v)]
    if not values:
        return {"mean": math.nan, "median": math.nan, "p95": math.nan, "std": math.nan}
    return {"mean": float(np.mean(values)), "median": float(np.median(values)),
            "p95": percentile(values, 95), "std": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0}


def _mean_or_nan(values: list[float]) -> float:
    return float(np.mean(values)) if values else math.nan


def summarize_series(queries: pd.DataFrame, capture: CaptureSummary | None) -> dict:
    """
    One benchmark series (one condition x run x method x cache mode) -> one row.
    Latency statistics use SUCCESSFUL queries only; failures lower the success rate.
    """
    n = len(queries)
    ok = queries[queries["ok"]]
    stats = latency_stats(ok["query_ms"].tolist())
    row = {
        "queries": n,
        "successes": int(len(ok)),
        "success_rate": 100.0 * len(ok) / n if n else math.nan,
        "mean_ms": stats["mean"], "median_ms": stats["median"],
        "p95_ms": stats["p95"], "std_ms": stats["std"],
        "app_retransmissions": int(queries["app_retrans"].sum()),
        "retrans_per_query": float(queries["app_retrans"].sum()) / n if n else math.nan,
        "first_query_ms": float(ok["query_ms"].iloc[0]) if len(ok) else math.nan,
        "later_query_ms": float(ok["query_ms"].iloc[1:].mean()) if len(ok) > 1 else math.nan,
        "packets": math.nan, "bytes": math.nan, "packets_per_query": math.nan,
        "bytes_per_query": math.nan, "pcap_retransmissions": math.nan,
        "tcp_connections": math.nan, "tcp_handshake_ms": math.nan, "tls_handshake_ms": math.nan,
    }
    if capture is not None and n:
        row.update({
            "packets": capture.packets, "bytes": capture.bytes,
            "packets_per_query": capture.packets / n, "bytes_per_query": capture.bytes / n,
            "pcap_retransmissions": capture.retransmissions,
            "tcp_connections": capture.tcp_connections,
            "tcp_handshake_ms": _mean_or_nan(capture.tcp_handshake_ms),
            "tls_handshake_ms": _mean_or_nan(capture.tls_handshake_ms),
        })
    return row


def aggregate_runs(runs: pd.DataFrame) -> pd.DataFrame:
    """Mean and standard deviation across the runs of each series (the report table)."""
    pieces = []
    grouped = runs.groupby(GROUP, sort=False)
    for metric in RUN_METRICS:
        if metric not in runs.columns:
            continue
        agg = grouped[metric].agg(["mean", "std"]).rename(
            columns={"mean": f"{metric}_mean", "std": f"{metric}_std"})
        pieces.append(agg)
    out = pd.concat(pieces, axis=1).reset_index()
    out.insert(len(GROUP), "runs", grouped.size().values)
    std_cols = [c for c in out.columns if c.endswith("_std")]
    out[std_cols] = out[std_cols].fillna(0.0)          # one run -> no spread
    return out


def _pm(mean, std, digits=1) -> str:
    if mean is None or (isinstance(mean, float) and math.isnan(mean)):
        return "n/a"
    return f"{mean:.{digits}f} ± {std:.{digits}f}"


def summary_table(summary: pd.DataFrame) -> pd.DataFrame:
    """Human-friendly version of the aggregate (strings 'mean ± std')."""
    rows = []
    for _, r in summary.iterrows():
        rows.append({
            "condition": r["condition"], "method": r["method"], "cache": r["cache"],
            "mean ms": _pm(r["mean_ms_mean"], r["mean_ms_std"]),
            "median ms": _pm(r["median_ms_mean"], r["median_ms_std"]),
            "p95 ms": _pm(r["p95_ms_mean"], r["p95_ms_std"]),
            "success %": _pm(r["success_rate_mean"], r["success_rate_std"]),
            "packets/query": _pm(r["packets_per_query_mean"], r["packets_per_query_std"]),
            "bytes/query": _pm(r["bytes_per_query_mean"], r["bytes_per_query_std"], 0),
            "retrans/query": _pm(r["retrans_per_query_mean"], r["retrans_per_query_std"], 2),
        })
    return pd.DataFrame(rows)


def to_markdown(df: pd.DataFrame) -> str:
    """Tiny markdown table writer (avoids needing the 'tabulate' package)."""
    header = "| " + " | ".join(df.columns) + " |"
    divider = "| " + " | ".join("---" for _ in df.columns) + " |"
    body = ["| " + " | ".join(str(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join([header, divider, *body])
