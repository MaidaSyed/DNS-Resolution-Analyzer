"""
Tests for the iterative resolver (F2) and reliability logic (F3), run against
the fake DNS hierarchy on 127.0.0.x (see fake_hierarchy.py).
Run:  pytest tests/test_resolver.py -v
"""
import pytest

from dns_analyzer.dns import Rcode, RType
from dns_analyzer.resolver import (DnsTransport, IterativeResolver, NameServer,
                                   QueryFailure, QueryTimeout, format_trace, is_subdomain)
from fake_hierarchy import AUTH2_IP, AUTH_IP, ROOT_IP, TLD_IP, Hierarchy


@pytest.fixture
def fixed_order(monkeypatch):
    """The resolver shuffles equal-priority servers; pin it so tests are repeatable."""
    monkeypatch.setattr("dns_analyzer.resolver.iterative.random.sample",
                        lambda seq, k: list(seq))


def make_resolver(h, timeout=0.15, attempts=3, **kwargs):
    transport = DnsTransport(port=h.port, timeout=timeout, attempts=attempts)
    return IterativeResolver(transport, [NameServer("a.root.", ROOT_IP)], **kwargs)


def answer_ips(result):
    return [rr.rdata for rr in result.answers if rr.rtype == RType.A]


# --------------------------------------------------------------- helpers ---
def test_is_subdomain():
    assert is_subdomain("www.example.test.", "test.")
    assert is_subdomain("www.example.test.", ".")
    assert is_subdomain("test.", "test.")
    assert not is_subdomain("notest.", "test.")      # label boundary matters
    assert not is_subdomain("test.", "example.test.")


# ------------------------------------------------------- the main scenario --
def test_full_iterative_resolution_root_tld_authoritative():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("www.example.test")
        assert result.ok and answer_ips(result) == ["10.10.3.30"]
        assert [x.server.ip for x in result.hops] == [ROOT_IP, TLD_IP, AUTH_IP]
        assert [x.outcome for x in result.hops] == ["referral", "referral", "answer"]
        assert [x.zone for x in result.hops] == [".", "test.", "example.test."]
        assert result.hops[2].aa is True and result.hops[0].aa is False
        # every query must be non-recursive (RD=0) and each server saw exactly one
        for server in h.servers.values():
            assert len(server.log) == 1 and server.log[0][2] is False


def test_glue_is_used_and_shown_in_trace():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("www.example.test")
        assert any("127.0.0.20 (glue)" in line for line in result.hops[0].lines)
        text = format_trace(result)
        assert "ROOT" in text and "TLD" in text and "AUTH" in text
        assert "REFERRAL" in text and "ANSWER" in text and "www.example.test. 300 IN A 10.10.3.30" in text


# ------------------------------------------------------------------ CNAME --
def test_cname_followed_when_server_returns_whole_chain():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("alias.example.test")
        assert result.ok and len(result.hops) == 3
        assert [rr.rtype for rr in result.answers] == [RType.CNAME, RType.A]
        assert answer_ips(result) == ["10.10.3.30"]


def test_cname_to_other_zone_restarts_from_root():
    with Hierarchy(auth_kwargs={"include_cname_targets": False}) as h:
        result = make_resolver(h).resolve("ext.example.test")
        assert result.ok and answer_ips(result) == ["10.10.9.9"]   # host.noglue.test.
        assert result.answers[0].rtype == RType.CNAME
        assert result.hops[3].server.ip == ROOT_IP and result.hops[3].qname == "host.noglue.test."


def test_cname_loop_is_detected():
    with Hierarchy(auth_kwargs={"include_cname_targets": False}) as h:
        result = make_resolver(h).resolve("loop1.example.test")
        assert not result.ok and "loop" in result.error.lower()


# ------------------------------------------------------- negative answers --
def test_nxdomain_from_authoritative_server():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("nothere.example.test")
        assert not result.ok and result.outcome == "nxdomain" and result.rcode == Rcode.NXDOMAIN
        assert len(result.hops) == 3 and "NXDOMAIN" in format_trace(result)


def test_nxdomain_from_root_for_unknown_tld():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("foo.invalid")
        assert result.outcome == "nxdomain" and len(result.hops) == 1


def test_nodata_when_type_missing():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("www.example.test", RType.AAAA)
        assert result.outcome == "nodata" and result.rcode == Rcode.NOERROR
        assert result.answers == [] and not result.ok


# --------------------------------------------------------------- no glue ---
def test_referral_without_glue_resolves_nameserver_first():
    with Hierarchy() as h:
        result = make_resolver(h).resolve("host.noglue.test")
        assert result.ok and answer_ips(result) == ["10.10.9.9"]
        nested = [x for x in result.hops if x.depth == 1]
        assert nested and nested[-1].qname == "ns1.example.test." and nested[-1].outcome == "answer"
        assert any("no glue" in line for x in result.hops for line in x.lines)


def test_glueless_loop_stopped_by_depth_limit():
    with Hierarchy() as h:
        result = make_resolver(h, max_ns_depth=0).resolve("host.noglue.test")
        assert not result.ok and result.error


# -------------------------------------------------------------- reliability --
def test_retransmission_recovers_from_lost_packet():
    with Hierarchy(auth_kwargs={"drop_first": 1}) as h:
        resolver = make_resolver(h, timeout=0.1)
        result = resolver.resolve("www.example.test")
        assert result.ok and result.hops[2].attempts == 2
        assert result.retransmissions == 1 and resolver.transport.stats.retransmissions == 1
        assert "1 retransmission" in format_trace(result)


def test_exponential_backoff_waits_longer_each_time():
    with Hierarchy(auth_kwargs={"drop_first": 2}) as h:
        transport = DnsTransport(port=h.port, timeout=0.1, attempts=3, backoff=2.0)
        resolver = IterativeResolver(transport, [NameServer("a.root.", ROOT_IP)])
        result = resolver.resolve("www.example.test")
        assert result.ok and result.hops[2].attempts == 3
        assert result.total_ms >= 100 + 200 - 40      # waited ~0.1 s then ~0.2 s


def test_tc_bit_triggers_tcp_fallback():
    with Hierarchy(auth_kwargs={"truncate_udp": True}) as h:
        resolver = make_resolver(h)
        result = resolver.resolve("www.example.test")
        assert result.ok and result.hops[2].used_tcp
        assert resolver.transport.stats.tcp_fallbacks == 1
        assert h.servers["auth"].log[-1][3] == "tcp" and "retried over TCP" in format_trace(result)


def test_failover_to_second_nameserver_when_first_is_dead(fixed_order):
    with Hierarchy(auth2=True, auth_kwargs={"mode": "dead"}) as h:
        result = make_resolver(h, timeout=0.05, attempts=2).resolve("www.example.test")
        assert result.ok
        auth_hops = [x for x in result.hops if x.zone == "example.test."]
        assert {x.server.ip for x in auth_hops} == {AUTH_IP, AUTH2_IP}
        assert any(x.outcome == "failed" and "no reply" in x.detail for x in auth_hops)
        assert "trying next server" in format_trace(result)


def test_failover_on_servfail(fixed_order):
    with Hierarchy(auth2=True, auth_kwargs={"mode": "servfail"}) as h:
        result = make_resolver(h, timeout=0.1).resolve("www.example.test")
        assert result.ok and answer_ips(result) == ["10.10.3.30"]
        failed = [x for x in result.hops if x.outcome == "failed"]
        assert len(failed) == 1 and "SERVFAIL" in failed[0].detail


def test_all_nameservers_dead_gives_clean_error():
    with Hierarchy(auth_kwargs={"mode": "dead"}) as h:
        result = make_resolver(h, timeout=0.05, attempts=2).resolve("www.example.test")
        assert not result.ok and "all nameservers" in result.error


def test_closed_port_fails_fast_not_after_full_timeout():
    transport = DnsTransport(port=9, timeout=2.0, attempts=3)       # nothing listens
    with pytest.raises(QueryFailure) as info:
        from dns_analyzer.dns import make_query
        transport.exchange("127.0.0.77", make_query("a.test"))
    assert not isinstance(info.value, QueryTimeout)


def test_timeout_exception_and_stats():
    with Hierarchy(root_kwargs={"mode": "dead"}) as h:
        transport = DnsTransport(port=h.port, timeout=0.05, attempts=2)
        from dns_analyzer.dns import make_query
        with pytest.raises(QueryTimeout):
            transport.exchange(ROOT_IP, make_query("a.test"))
        s = transport.stats
        assert (s.queries, s.packets_sent, s.retransmissions, s.timeouts, s.failures) == (1, 2, 1, 1, 1)


def test_referral_loop_is_not_followed_forever():
    with Hierarchy(self_referring_root=True) as h:
        result = make_resolver(h).resolve("www.example.test")
        assert not result.ok and result.error
        assert len(result.hops) <= 3


def test_nameserver_selection_prefers_server_without_failures(fixed_order):
    with Hierarchy(auth2=True, auth_kwargs={"mode": "dead"}) as h:
        resolver = make_resolver(h, timeout=0.05, attempts=1)
        resolver.resolve("www.example.test")                        # learns AUTH_IP is bad
        second = resolver.resolve("www.example.test")
        auth_hops = [x for x in second.hops if x.zone == "example.test."]
        assert auth_hops[0].server.ip == AUTH2_IP and len(auth_hops) == 1


# ------------------------------------------------ command-line integration --
def test_cli_iterative_end_to_end(capsys):
    import analyzer
    with Hierarchy() as h:
        code = analyzer.main(["iterative", "www.example.test", "--root", ROOT_IP,
                              "--port", str(h.port), "--timeout", "0.5"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Iterative resolution of www.example.test. A" in out
    assert "REFERRAL" in out and "10.10.3.30" in out and "3 queries" in out


def test_cli_returns_nonzero_for_nxdomain(capsys):
    import analyzer
    with Hierarchy() as h:
        code = analyzer.main(["iterative", "nothere.example.test", "--root", ROOT_IP,
                              "--port", str(h.port), "--timeout", "0.5"])
    assert code == 1 and "NXDOMAIN" in capsys.readouterr().out
