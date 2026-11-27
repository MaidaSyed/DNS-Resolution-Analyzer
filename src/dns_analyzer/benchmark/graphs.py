"""graphs.py - Draws the benchmark graphs (matplotlib, saved as PNG files)."""
from __future__ import annotations

import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")            # draw to files; no window needed
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

METHOD_ORDER = ["iterative", "do53", "dot_fresh", "dot_reused", "doh_fresh", "doh_reused"]
METHOD_LABELS = {"iterative": "Iterative (own resolver)", "do53": "Do53 stub",
                 "dot_fresh": "DoT new conn.", "dot_reused": "DoT reused conn.",
                 "doh_fresh": "DoH new conn.", "doh_reused": "DoH reused conn."}
COLORS = {"iterative": "#4c72b0", "do53": "#55a868", "dot_fresh": "#dd8452",
          "dot_reused": "#c44e52", "doh_fresh": "#8172b3", "doh_reused": "#937860"}
CONDITION_ORDER = ["good", "moderate", "poor"]


def _methods_present(df: pd.DataFrame) -> list[str]:
    return [m for m in METHOD_ORDER if m in set(df["method"])]


def _conditions_present(df: pd.DataFrame) -> list[str]:
    return [c for c in CONDITION_ORDER if c in set(df["condition"])]


def _grouped_bars(df, value, err, title, ylabel, path, extra_markers=None, log=False):
    methods, conditions = _methods_present(df), _conditions_present(df)
    if not methods or not conditions or df[value].isna().all():
        return None
    fig, ax = plt.subplots(figsize=(9, 5))
    width = 0.8 / len(methods)
    for i, method in enumerate(methods):
        xs, ys, es, ms = [], [], [], []
        for j, cond in enumerate(conditions):
            row = df[(df["method"] == method) & (df["condition"] == cond)]
            xs.append(j + (i - (len(methods) - 1) / 2) * width)
            ys.append(float(row[value].iloc[0]) if len(row) else math.nan)
            es.append(float(row[err].iloc[0]) if len(row) and err else 0.0)
            ms.append(float(row[extra_markers].iloc[0]) if len(row) and extra_markers else math.nan)
        ax.bar(xs, ys, width, yerr=es if err else None, capsize=3, color=COLORS[method],
               label=METHOD_LABELS[method])
        if extra_markers:
            ax.scatter(xs, ms, marker="D", color="black", s=18, zorder=3,
                       label="95th percentile" if i == 0 else None)
    ax.set_xticks(range(len(conditions)))
    ax.set_xticklabels([c.capitalize() for c in conditions])
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if log:
        ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def draw_all(summary: pd.DataFrame, queries: pd.DataFrame, out_dir: str | Path) -> list[Path]:
    """Create every graph that the available data allows. Returns the files written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    made: list[Path] = []

    def add(path):
        if path:
            made.append(path)

    for cache in ("cold", "warm"):
        part = summary[summary["cache"] == cache]
        add(_grouped_bars(part, "mean_ms_mean", "mean_ms_std",
                          f"Resolution time, {cache} cache (bars: mean ± std over runs, diamonds: p95)",
                          "milliseconds (log scale)", out / f"latency_{cache}.png",
                          extra_markers="p95_ms_mean", log=True))
    cold = summary[summary["cache"] == "cold"]
    add(_grouped_bars(cold, "success_rate_mean", "success_rate_std", "Success rate (cold cache)",
                      "% of queries answered", out / "success_rate.png"))
    add(_grouped_bars(cold, "packets_per_query_mean", "packets_per_query_std",
                      "Packets per resolution (captured on the client link)",
                      "packets", out / "packets_per_query.png"))
    add(_grouped_bars(cold, "bytes_per_query_mean", "bytes_per_query_std",
                      "Bytes on the wire per resolution (handshakes included)",
                      "bytes", out / "bytes_per_query.png", log=True))
    reuse = cold[cold["method"].isin(["dot_fresh", "dot_reused", "doh_fresh", "doh_reused"])]
    add(_grouped_bars(reuse, "mean_ms_mean", "mean_ms_std", "Fresh vs reused connection (cold cache)",
                      "milliseconds", out / "connection_reuse.png"))
    add(_grouped_bars(cold, "retrans_per_query_mean", "retrans_per_query_std",
                      "Application-level retransmissions per query", "retransmissions",
                      out / "retransmissions.png"))

    # Latency distribution (CDF) per condition: shows the long tail caused by loss.
    ok = queries[(queries["ok"]) & (queries["cache"] == "cold")]
    for cond in _conditions_present(ok):
        fig, ax = plt.subplots(figsize=(8, 5))
        for method in _methods_present(ok):
            values = np.sort(ok[(ok["condition"] == cond) & (ok["method"] == method)]["query_ms"].to_numpy())
            if len(values):
                ax.step(values, np.arange(1, len(values) + 1) / len(values), where="post",
                        color=COLORS[method], label=METHOD_LABELS[method])
        ax.set_xscale("log")
        ax.set_xlabel("resolution time (ms, log scale)")
        ax.set_ylabel("fraction of queries finished")
        ax.set_title(f"Latency distribution, {cond} network (cold cache)")
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8)
        fig.tight_layout()
        path = out / f"latency_cdf_{cond}.png"
        fig.savefig(path, dpi=130)
        plt.close(fig)
        made.append(path)
    return made
