"""
Integration tests against the REAL testbed (network namespaces + BIND9).
They are skipped unless you are root AND set RUN_LAB_TESTS=1, because they
create namespaces and start four BIND servers:

    sudo RUN_LAB_TESTS=1 .venv/bin/python -m pytest tests/test_lab_integration.py -v
"""
import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(
    not (os.geteuid() == 0 and os.environ.get("RUN_LAB_TESTS") == "1"),
    reason="needs root and RUN_LAB_TESTS=1 (starts the namespace testbed)")


def analyzer(*args, check=True):
    proc = subprocess.run([sys.executable, str(ROOT / "analyzer.py"), *args],
                          capture_output=True, text=True, cwd=ROOT, timeout=120)
    if check:
        assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc


@pytest.fixture(scope="module", autouse=True)
def lab():
    if not (ROOT / "certs" / "resolver.crt").exists():
        subprocess.run(["bash", str(ROOT / "scripts" / "make_certs.sh")], check=True)
    analyzer("lab", "up")
    yield
    analyzer("lab", "down", check=False)


def test_iterative_follows_root_tld_authoritative_on_real_bind():
    out = analyzer("iterative", "www.example.test", "--lab").stdout
    assert "ROOT zone '.'" in out and "TLD  zone 'test.'" in out and "AUTH zone 'example.test.'" in out
    assert "10.10.3.20 (glue)" in out and "10.10.3.30 (glue)" in out
    assert "www.example.test. 300 IN A 10.10.3.30" in out and "3 queries" in out


def test_iterative_follows_cname_and_reports_nxdomain():
    assert "CNAME www.example.test." in analyzer("iterative", "alias.example.test", "--lab").stdout
    proc = analyzer("iterative", "nothere.example.test", "--lab", check=False)
    assert proc.returncode == 1 and "NXDOMAIN" in proc.stdout


def test_tc_bit_fallback_to_tcp_with_real_bind():
    out = analyzer("iterative", "big.example.test", "--type", "TXT", "--lab").stdout
    assert "retried over TCP" in out


def test_do53_dot_doh_all_answer_through_the_recursive_resolver():
    for mode in ("do53", "dot", "doh"):
        out = analyzer(mode, "www.example.test", "--lab").stdout
        assert "10.10.3.30" in out, mode


def test_dot_and_doh_reuse_one_connection():
    for mode in ("dot", "doh"):
        out = analyzer(mode, "www.example.test", "--lab", "--repeat", "2").stdout
        assert out.count("connection reused: False") == 1 and out.count("connection reused: True") == 1


def test_untrusted_certificate_is_rejected():
    proc = analyzer("dot", "www.example.test", "--lab", "--cafile", "/etc/ssl/certs/ca-certificates.crt",
                    check=False)
    assert proc.returncode == 1 and "CERTIFICATE_VERIFY_FAILED" in proc.stdout


def test_quick_benchmark_produces_results(tmp_path):
    out = tmp_path / "results"
    analyzer("benchmark", "--no-netem", "--conditions", "good", "--names", "5",
             "--methods", "iterative,do53,dot_reused", "--out", str(out),
             "--captures", str(tmp_path / "caps"))
    assert (out / "benchmark_summary.md").exists()
    assert any((tmp_path / "caps").glob("*.pcap"))
