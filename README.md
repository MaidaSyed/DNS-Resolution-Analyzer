# DNS Resolution Analyzer

**Iterative resolver built from raw packets, and a DoT / DoH comparison** — CS3001 Computer Networks, FAST-NUCES Karachi (Project 17).

The tool makes DNS resolution *visible and measurable*. It contains:

| Mode | What it does |
|---|---|
| `iterative` | Our own resolver: builds DNS packets byte by byte and walks root → TLD → authoritative, with a hop-by-hop trace |
| `do53` | Plain DNS (UDP/53, TCP fallback) to a recursive resolver |
| `dot` | DNS over TLS 1.3, TCP 853, length-prefixed messages, connection reuse |
| `doh` | DNS over HTTPS, HTTP/2 POST `application/dns-message`, connection reuse |
| `benchmark` | 3 network conditions × 3 runs × all methods → CSV, statistics, graphs, pcaps |
| `analyze` | Reads a tcpdump `.pcap`: packets, bytes, handshakes, retransmissions |

## 1. Architecture

```
 lab-client            lab-router (R1, forwarding)                lab-resolver  (BIND9 recursive)
 10.10.1.10 ──eth0──[10.10.1.1]                    [10.10.2.1]──── 10.10.2.53   UDP/TCP 53, TCP 853, TCP 443
   ▲ netem (RTT/loss)  [10.10.3.1 bridge br3]
                          │        │        │
                     lab-root  lab-tld  lab-auth    (BIND9 authoritative)
                    10.10.3.10  .20      .30         ".", "test.", "example.test."
```

* Every box is a Linux **network namespace**; links are veth pairs; the router namespace has IP forwarding on.
* `tc netem` impairs **only the client link** (delay = RTT/2 in each direction, loss rate applied per direction), as the proposal specifies. The three links of the DNS hierarchy get ~5 ms RTT so the resolver sits "near" the hierarchy.
* Private DNS tree: root `.` → `test.` → `example.test.` (`www.example.test`, `alias` CNAME, `host001..host100` for the benchmark, `big` TXT that forces the TC bit).
* One BIND9 (9.18) instance per server. The recursive resolver uses BIND too, because 9.18 natively serves Do53, **DoT** (`listen-on port 853 tls`) and **DoH** (`listen-on port 443 tls http`), so one daemon covers F6 (no Unbound/dnsdist needed).

## 2. Project layout

```
analyzer.py                      command line entry point
src/dns_analyzer/
  dns/records.py, codec.py       F1  DNS message encoder/decoder (struct only)
  resolver/iterative.py          F2  iterative engine, glue, CNAME, trace
  resolver/reliability.py        F3  timeouts, retransmission, back-off, TCP fallback
  clients/do53.py dot.py doh.py  F4/F5 clients (+ common.py: QueryResult, TCP framing)
  lab.py                         F6/F7 testbed: namespaces, BIND start, netem, tcpdump, rndc
  benchmark/runner.py            F7  automated benchmark
  benchmark/metrics.py graphs.py F7  statistics and graphs
  benchmark/capture.py           F8  pcap analysis
configs/bind/*.conf, zones/      BIND configuration templates and zone files
scripts/setup.sh make_certs.sh   one-time setup, TLS certificates
network/topology.py              wrapper:  python network/topology.py up|down|status|netem
tests/                           unit + integration tests
results/ captures/               benchmark output (CSV, graphs) and pcap evidence
```

## 3. Setup (Ubuntu 24.04)

```bash
sudo apt install bind9 bind9-utils bind9-dnsutils iproute2 tcpdump openssl tshark   # tshark optional
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
bash scripts/setup.sh         # checks tools, netem, makes certs, creates /usr/local/sbin/named-lab
```

`setup.sh` creates a copy of `named` because Ubuntu's AppArmor profile stops `/usr/sbin/named` from reading files in your home folder. Certificates and private keys go to `certs/` (git-ignored: **never commit them**).

## 4. Usage

Commands that touch namespaces need `sudo`. Use the venv's Python: `sudo .venv/bin/python ...`.

```bash
sudo .venv/bin/python analyzer.py lab up                  # build the testbed, start 4 BIND servers
sudo .venv/bin/python analyzer.py lab status

sudo .venv/bin/python analyzer.py iterative www.example.test --lab
sudo .venv/bin/python analyzer.py do53 www.example.test --lab
sudo .venv/bin/python analyzer.py dot  www.example.test --lab --repeat 3
sudo .venv/bin/python analyzer.py doh  www.example.test --lab --repeat 3
sudo .venv/bin/python analyzer.py iterative alias.example.test --lab               # CNAME chasing
sudo .venv/bin/python analyzer.py iterative big.example.test --type TXT --lab      # TC bit -> TCP

sudo .venv/bin/python analyzer.py lab netem poor          # 200 ms RTT, 5 % loss (good | moderate | poor | clear)
sudo .venv/bin/python analyzer.py lab flush               # empty the resolver cache
sudo .venv/bin/python analyzer.py lab down
```

`--lab` runs the client inside the `lab-client` namespace (10.10.1.10). Without `--lab` the commands use `--server/--url/--root`, so they also work against public resolvers (e.g. `dot www.example.com --server 1.1.1.1 --hostname one.one.one.one`).

### Demo script (matches the proposal's POC)

1. `lab up`, then `iterative www.example.test --lab` – show the root, TLD, authoritative hops, glue, RD=0.
2. `do53`, `dot --repeat 2`, `doh --repeat 2` – same name through the resolver; note handshake times and reuse.
3. `lab netem poor`, then `iterative ... --lab` several times – retransmissions and the latency gap. `lab netem clear` afterwards.
4. `benchmark --quick` (or the full run) – show `results/benchmark_summary.md` and `results/graphs/`.

## 5. Benchmark

```bash
sudo .venv/bin/python analyzer.py benchmark --quick          # 20 names, 1 run, a few minutes
sudo .venv/bin/python analyzer.py benchmark                  # full: 100 names x 3 runs x 3 conditions
sudo .venv/bin/python analyzer.py benchmark --conditions poor --runs 1 --methods iterative,dot_fresh,dot_reused
```

Series: `iterative`, `do53`, `dot_fresh`/`dot_reused`, `doh_fresh`/`doh_reused`. *fresh* = a new TCP+TLS connection per query, *reused* = one connection for the whole series.
Cache modes: **cold** = resolver cache flushed (`rndc flush`) before *every* query; **warm** = names resolved once beforehand, then measured. Our iterative resolver has no cache, so it only has a cold series.

Output in `results/`:

* `benchmark_queries.csv` every query (time, success, retransmissions, ...)
* `benchmark_runs.csv` one row per condition × run × method × cache (mean, median, p95, success rate, packets/bytes from the pcap, handshake times)
* `benchmark_summary.csv` / `.md` mean ± standard deviation over the runs
* `graphs/*.png` latency (cold/warm), success rate, packets and bytes per query, connection reuse, retransmissions, latency CDFs

The full benchmark sends about 10 000 queries and can take well over an hour on the poor network. `python analyzer.py report` rebuilds tables/graphs from the CSVs.

Definitions: latency statistics use *successful* queries only (failures lower the success rate). Packets/bytes are counted on the client link from the pcap, **including TCP/TLS/HTTP/2 headers and handshakes**, divided by the number of queries in the series.

## 6. Packet capture (F8)

The benchmark starts `tcpdump` in the client namespace for every series (`captures/<condition>_run<N>_<method>_<cache>.pcap`). Analyse any capture:

```bash
python analyzer.py analyze captures/poor_run1_dot_fresh_cold.pcap --queries 100
```

It reports packets, bytes, TCP handshake time (SYN → SYN/ACK), TLS handshake time (ClientHello → client Finished), TCP retransmissions (same sequence range twice) and UDP DNS retransmissions (same ID from the same source port twice). On a real capture this analyzer gave exactly the same packet count (619), byte total (123 220) and connection count as `tshark`.

**Manual Wireshark checks** (open a `.pcap`):

| What | Display filter |
|---|---|
| DNS messages | `dns` |
| Truncated reply (TC bit) | `dns.flags.truncated == 1` |
| TCP handshakes | `tcp.flags.syn == 1` |
| TLS handshakes | `tls.handshake` |
| TCP retransmissions | `tcp.analysis.retransmission` |
| DoH requests (needs key log, below) | `http2` |

**Decrypting DoH/DoT:** run the client with a TLS key log, then give the file to Wireshark (Edit → Preferences → Protocols → TLS → "(Pre)-Master-Secret log filename"):

```bash
sudo SSLKEYLOGFILE=/tmp/keys.log .venv/bin/python analyzer.py doh www.example.test --lab --repeat 2
tshark -r captures/x.pcap -o tls.keylog_file:/tmp/keys.log -Y http2
```

## 7. Tests

```bash
python -m pytest -q                                              # 85 tests, no root needed
sudo RUN_LAB_TESTS=1 .venv/bin/python -m pytest tests/test_lab_integration.py -v   # 7 tests on the real testbed
```

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `this needs root` | use `sudo .venv/bin/python analyzer.py ...` |
| `servers did not become ready` | read `/tmp/dnslab/<node>/named.log` and `stdout.log`; usually AppArmor (run `bash scripts/setup.sh`) or a bad config |
| `tc netem failed ... unknown qdisc` | `sudo apt install linux-modules-extra-$(uname -r) && sudo modprobe sch_netem` |
| `lab up` complains about certificates | `bash scripts/make_certs.sh` |
| `CERTIFICATE_VERIFY_FAILED` | use `--lab` (picks `certs/ca.crt`) or `--cafile certs/ca.crt` |
| leftover namespaces after a crash | `sudo .venv/bin/python analyzer.py lab down` |

## 9. Design notes and limitations

* **Caching:** the iterative resolver does not cache, by design (cold lookups are the thing measured).
* **Loss model:** the loss rate is applied to each direction of the client link, so a request/response pair is lost with probability about 1 − (1 − p)².
* **Byte counts in `QueryResult`** are DNS payload bytes; the *on-the-wire* totals come from the pcaps.
* **DoH handshake time** is not reported separately (httpx hides it): compare the first query with later ones, or read the pcap.
* **TLS 1.3 post-handshake stall:** BIND sends session tickets right after the handshake; if the client delays its ACK, Nagle's algorithm holds back the first DNS answer by ~40 ms. The DoT client therefore sets `TCP_QUICKACK` before reading the answer (without it about 10 % of fresh DoT queries took +40 ms).
* IPv4 only; no DNSSEC (the private root has no trust anchor).

## 10. AI-use disclosure

*Edit this section to match what the team actually did.* Generative AI (Claude, Anthropic) was used to help write and debug code and documentation for this project; the team reviewed, ran and takes responsibility for the result.
