"""
lab.py - Builds and controls the virtual testbed (feature F6 + the network
control part of F7). Needs root (sudo) because it creates network namespaces.

Topology (every box is a Linux network namespace, links are veth pairs):

   lab-client            lab-router                       lab-resolver
   10.10.1.10 --eth0--[10.10.1.1  r-client]               10.10.2.53
                       [10.10.2.1  r-res   ]--eth0------- (BIND: 53/853/443)
                       [10.10.3.1  br3 (bridge)]
                              |      |      |
                           lab-root lab-tld lab-auth
                          10.10.3.10 .20     .30   (BIND, authoritative)

* The router namespace has IP forwarding switched on: it is "R1".
* tc netem is applied to the CLIENT link only (both directions) to emulate
  the good / moderate / poor networks. The DNS-hierarchy links get a small
  fixed delay so the resolver is about 5 ms from root/TLD/authoritative.
"""
from __future__ import annotations

import os
import select
import shlex
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "configs" / "bind"
ZONE_DIR = CONFIG_DIR / "zones"
CERT_DIR = PROJECT_ROOT / "certs"
RUN_DIR = Path("/tmp/dnslab")

NAMESPACES = {k: f"lab-{k}" for k in ("client", "router", "resolver", "root", "tld", "auth")}
RESOLVER_IP = "10.10.2.53"
ROOT_IP = "10.10.3.10"
DNS_PREFIX = "10.10.3."

# DNS server nodes: name -> (ip, router-side bridge port, config template)
DNS_NODES = {
    "root": ("10.10.3.10", "p-root", "root.conf"),
    "tld": ("10.10.3.20", "p-tld", "tld.conf"),
    "auth": ("10.10.3.30", "p-auth", "auth.conf"),
}
INFRA_DELAY_MS = 5.0           # round trip resolver <-> DNS hierarchy


@dataclass(frozen=True)
class Condition:
    key: str
    label: str
    rtt_ms: float
    loss_pct: float


CONDITIONS = {
    "good": Condition("good", "C1: Good", 20, 0),
    "moderate": Condition("moderate", "C2: Moderate", 100, 2),
    "poor": Condition("poor", "C3: Poor", 200, 5),
}


class LabError(RuntimeError):
    pass


def require_root() -> None:
    if os.geteuid() != 0:
        raise LabError("this needs root: run it with sudo, e.g.  sudo .venv/bin/python analyzer.py ...")


def _run(cmd: list[str] | str, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise LabError(f"command failed: {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc


def ip(*args: str, ns: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    base = ["ip"] + (["-n", NAMESPACES[ns]] if ns else [])
    return _run(base + list(args), check=check)


def in_ns(ns: str, cmd: list[str]) -> list[str]:
    return ["ip", "netns", "exec", NAMESPACES[ns]] + cmd


# ---------------------------------------------------------------- bring up --
def namespaces_exist() -> bool:
    out = _run(["ip", "netns", "list"], check=False).stdout
    return any(line.split()[0] == NAMESPACES["router"] for line in out.splitlines() if line.strip())


def named_binary() -> str:
    """
    Ubuntu confines /usr/sbin/named with AppArmor, which blocks reading our
    project files. scripts/setup.sh makes an unconfined copy called named-lab.
    """
    for candidate in ("/usr/local/sbin/named-lab", "/usr/sbin/named"):
        if Path(candidate).exists():
            return candidate
    raise LabError("BIND is not installed: sudo apt install bind9 bind9-utils")


def up(verbose: bool = True) -> None:
    require_root()
    for tool in ("ip", "tc"):
        if not shutil.which(tool):
            raise LabError(f"'{tool}' not found: sudo apt install iproute2")
    if not (CERT_DIR / "resolver.crt").exists():
        raise LabError("no certificates yet: run  bash scripts/make_certs.sh")
    down(quiet=True)
    log = print if verbose else (lambda *a, **k: None)

    log("[lab] creating namespaces ...")
    for name in NAMESPACES.values():
        _run(["ip", "netns", "add", name])
        _run(["ip", "-n", name, "link", "set", "lo", "up"])
    _run(in_ns("router", ["sysctl", "-qw", "net.ipv4.ip_forward=1"]))

    log("[lab] wiring links and addresses ...")
    # client <-> router (10.10.1.0/24) and resolver <-> router (10.10.2.0/24)
    for node, node_ip, rt_if, rt_ip in (("client", "10.10.1.10", "r-client", "10.10.1.1"),
                                        ("resolver", RESOLVER_IP, "r-res", "10.10.2.1")):
        ip("link", "add", rt_if, "netns", NAMESPACES["router"], "type", "veth",
           "peer", "name", "eth0", "netns", NAMESPACES[node])
        ip("addr", "add", f"{rt_ip}/24", "dev", rt_if, ns="router")
        ip("link", "set", rt_if, "up", ns="router")
        ip("addr", "add", f"{node_ip}/24", "dev", "eth0", ns=node)
        ip("link", "set", "eth0", "up", ns=node)
        ip("route", "add", "default", "via", rt_ip, ns=node)
    # DNS servers share subnet 3 through a bridge ("switch") inside the router
    ip("link", "add", "br3", "type", "bridge", ns="router")
    ip("addr", "add", "10.10.3.1/24", "dev", "br3", ns="router")
    ip("link", "set", "br3", "up", ns="router")
    for node, (node_ip, port, _conf) in DNS_NODES.items():
        ip("link", "add", port, "netns", NAMESPACES["router"], "type", "veth",
           "peer", "name", "eth0", "netns", NAMESPACES[node])
        ip("link", "set", port, "master", "br3", ns="router")
        ip("link", "set", port, "up", ns="router")
        ip("addr", "add", f"{node_ip}/24", "dev", "eth0", ns=node)
        ip("link", "set", "eth0", "up", ns=node)
        ip("route", "add", "default", "via", "10.10.3.1", ns=node)

    log("[lab] starting BIND servers (root, tld, auth, resolver) ...")
    _start_bind()
    log("[lab] waiting for servers to answer ...")
    _wait_ready()
    try:
        set_infrastructure_delay(INFRA_DELAY_MS)
    except LabError as exc:
        log(f"[lab] WARNING: could not set infrastructure delay ({exc}); continuing without it")
    log("[lab] ready. Client namespace: lab-client (10.10.1.10), resolver 10.10.2.53")


def _render(template: Path, target: Path, rundir: Path) -> None:
    text = template.read_text()
    for key, value in (("@RUNDIR@", rundir), ("@ZONEDIR@", ZONE_DIR),
                       ("@CERTDIR@", CERT_DIR), ("@CONFDIR@", CONFIG_DIR)):
        text = text.replace(key, str(value))
    target.write_text(text)


def _start_bind() -> None:
    named = named_binary()
    nodes = {k: (ns_conf[2], k) for k, ns_conf in DNS_NODES.items()}
    nodes["resolver"] = ("resolver.conf", "resolver")
    for node, (template, _) in nodes.items():
        rundir = RUN_DIR / node
        shutil.rmtree(rundir, ignore_errors=True)
        rundir.mkdir(parents=True)
        if node == "resolver":
            _run(["rndc-confgen", "-a", "-k", "lab-key", "-c", str(rundir / "rndc.key")])
        conf = rundir / "named.conf"
        _render(CONFIG_DIR / template, conf, rundir)
        check = _run(["named-checkconf", str(conf)], check=False)
        if check.returncode != 0:
            raise LabError(f"bad BIND config for {node}:\n{check.stdout}{check.stderr}")
        out = open(rundir / "stdout.log", "w")
        subprocess.Popen(in_ns(node, [named, "-c", str(conf), "-f"]),
                         stdout=out, stderr=out, start_new_session=True)


def _wait_ready(timeout: float = 15.0) -> None:
    checks = [(ROOT_IP, "."), ("10.10.3.20", "test."), ("10.10.3.30", "example.test."),
              (RESOLVER_IP, "www.example.test.")]
    deadline = time.monotonic() + timeout
    pending = list(checks)
    while pending and time.monotonic() < deadline:
        server, name = pending[0]
        proc = _run(in_ns("client", ["dig", f"@{server}", name, "A" if "www" in name else "SOA",
                                     "+time=1", "+tries=1", "+short"]), check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            pending.pop(0)
        else:
            time.sleep(0.3)
    if pending:
        logs = "\n".join(f"--- {n} ---\n" + _tail(RUN_DIR / n / "stdout.log") + _tail(RUN_DIR / n / "named.log")
                         for n in ("root", "tld", "auth", "resolver"))
        raise LabError(f"servers did not become ready: {pending}\n{logs}")


def _tail(path: Path, lines: int = 8) -> str:
    try:
        return "\n".join(path.read_text().splitlines()[-lines:]) + "\n"
    except OSError:
        return ""


# --------------------------------------------------------------- tear down --
def down(quiet: bool = False) -> None:
    require_root()
    for name in NAMESPACES.values():
        pids = _run(["ip", "netns", "pids", name], check=False).stdout.split()
        for pid in pids:
            try:
                os.kill(int(pid), signal.SIGTERM)
            except (ProcessLookupError, ValueError):
                pass
    time.sleep(0.3)
    for name in NAMESPACES.values():
        for pid in _run(["ip", "netns", "pids", name], check=False).stdout.split():
            try:
                os.kill(int(pid), signal.SIGKILL)
            except (ProcessLookupError, ValueError):
                pass
        _run(["ip", "netns", "del", name], check=False)
    if not quiet:
        print("[lab] stopped; namespaces removed (logs kept in /tmp/dnslab)")


# -------------------------------------------------- network conditions (F7) --
def _netem(ns: str, dev: str, delay_ms: float, loss_pct: float) -> None:
    cmd = ["tc", "qdisc", "replace", "dev", dev, "root", "netem",
           "delay", f"{delay_ms:g}ms", "loss", f"{loss_pct:g}%"]
    proc = _run(in_ns(ns, cmd), check=False)
    if proc.returncode != 0:
        raise LabError(f"tc netem failed on {NAMESPACES[ns]}/{dev}: {proc.stderr.strip()} "
                       "(is the sch_netem module available? sudo modprobe sch_netem)")


def _clear_netem(ns: str, dev: str) -> None:
    _run(in_ns(ns, ["tc", "qdisc", "del", "dev", dev, "root"]), check=False)


def set_condition(cond: Condition) -> None:
    """
    Impair the client link. A link has two directions, so the one-way delay is
    RTT/2 on each side, and the loss rate applies to each direction.
    (Client eth0 egress = upstream, router r-client egress = downstream.)
    """
    require_root()
    for ns, dev in (("client", "eth0"), ("router", "r-client")):
        _netem(ns, dev, cond.rtt_ms / 2, cond.loss_pct)


def clear_condition() -> None:
    require_root()
    for ns, dev in (("client", "eth0"), ("router", "r-client")):
        _clear_netem(ns, dev)


def set_infrastructure_delay(rtt_ms: float) -> None:
    """~5 ms round trip between the resolver and the DNS hierarchy (subnet 3 links)."""
    for node, (_ip, port, _c) in DNS_NODES.items():
        _netem(node, "eth0", rtt_ms / 4, 0)
        _netem("router", port, rtt_ms / 4, 0)


# ------------------------------------------------------------- resolver ctl --
def flush_resolver_cache() -> None:
    """Empty the recursive resolver's cache (makes the next lookup 'cold')."""
    proc = _run(in_ns("resolver", ["rndc", "-s", "127.0.0.1", "-p", "9953",
                                   "-k", str(RUN_DIR / "resolver" / "rndc.key"), "flush"]), check=False)
    if proc.returncode != 0:
        raise LabError(f"rndc flush failed: {proc.stderr.strip()}")


def prime_resolver_cache(names: list[str]) -> None:
    """Fill the resolver's cache by resolving `names` from inside the resolver namespace."""
    for i in range(0, len(names), 50):
        _run(in_ns("resolver", ["dig", f"@{RESOLVER_IP}", "+time=5", "+tries=2", "+short"]
                   + names[i:i + 50]), check=False)


# ------------------------------------------------------------------ capture --
class Capture:
    """tcpdump running inside the client namespace, writing a pcap file."""

    def __init__(self, path: Path, iface: str = "eth0") -> None:
        self.path = Path(path)
        self.iface = iface
        self.proc: subprocess.Popen | None = None

    def start(self) -> "Capture":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.unlink(missing_ok=True)
        # -Z root keeps write access to our files; -U and --immediate-mode make tcpdump
        # hand over/write every packet at once (otherwise libpcap buffers them for
        # about a second and a short capture would lose its last packets).
        self.proc = subprocess.Popen(
            in_ns("client", ["tcpdump", "-i", self.iface, "-n", "-U", "--immediate-mode",
                             "-s", "0", "-Z", "root", "-w", str(self.path), "ip"]),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        # The pcap file appears slightly BEFORE tcpdump is really listening, so
        # wait for its own "listening on" message; otherwise early packets are lost.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.proc.stderr], [], [], 0.1)
            if ready:
                line = self.proc.stderr.readline()
                if "listening on" in line:
                    return self
                if not line and self.proc.poll() is not None:
                    break
        self.stop()
        raise LabError("tcpdump did not start (is it installed? sudo apt install tcpdump)")

    def stop(self) -> Path:
        if self.proc:
            time.sleep(0.4)                       # let the last packets arrive
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.communicate(timeout=5)       # also drains stderr
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.communicate()
            self.proc = None
        return self.path


def enter_client_namespace() -> None:
    """
    Move THIS Python process into the client namespace, so every socket it
    opens afterwards starts at 10.10.1.10. (Control commands such as tc or
    rndc keep working because they use `ip netns exec` themselves.)
    """
    require_root()
    path = f"/var/run/netns/{NAMESPACES['client']}"
    if not os.path.exists(path):
        raise LabError("the lab is not running: start it with  sudo .venv/bin/python analyzer.py lab up")
    fd = os.open(path, os.O_RDONLY)
    try:
        os.setns(fd, os.CLONE_NEWNET)
    finally:
        os.close(fd)


def status() -> str:
    lines = []
    for key, name in NAMESPACES.items():
        exists = name in _run(["ip", "netns", "list"], check=False).stdout
        pids = _run(["ip", "netns", "pids", name], check=False).stdout.split() if exists else []
        lines.append(f"  {name:<14} {'present' if exists else 'MISSING':<8} processes: {len(pids)}")
    return "\n".join(lines)
