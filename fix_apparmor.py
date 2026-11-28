"""One-time patch for src/dns_analyzer/lab.py: run unconfined copies of named and tcpdump
(Ubuntu's AppArmor profiles block signalling them) and never crash while stopping processes."""
import pathlib, sys

path = pathlib.Path("src/dns_analyzer/lab.py")
text = path.read_text()
if "_lab_binary" in text:
    sys.exit("already patched - nothing to do")

def replace(old, new):
    global text
    if old not in text:
        sys.exit("could not patch: this part of lab.py is different from expected:\n" + old[:80])
    text = text.replace(old, new, 1)

# 1) one helper that creates an unconfined copy of a program
replace('''def named_binary() -> str:
    """
    Ubuntu confines /usr/sbin/named with AppArmor, which blocks reading our
    project files. scripts/setup.sh makes an unconfined copy called named-lab.
    """
    for candidate in ("/usr/local/sbin/named-lab", "/usr/sbin/named"):
        if Path(candidate).exists():
            return candidate
    raise LabError("BIND is not installed: sudo apt install bind9 bind9-utils")
''', '''def _lab_binary(tool: str, copy_name: str) -> str:
    """
    Ubuntu confines /usr/sbin/named and /usr/bin/tcpdump with AppArmor profiles
    that attach to the program's PATH. A confined tcpdump cannot even be stopped
    by us (kill -> 'Permission denied'). A copy stored under another name is not
    confined, so the lab always runs its own copy (created once, needs root).
    """
    target = Path("/usr/local/sbin") / copy_name
    if not target.exists():
        source = shutil.which(tool) or f"/usr/sbin/{tool}"
        if not Path(source).exists():
            raise LabError(f"{tool} is not installed: sudo apt install bind9 bind9-utils tcpdump")
        shutil.copy2(source, target)
        os.chmod(target, 0o755)
    return str(target)


def named_binary() -> str:
    return _lab_binary("named", "named-lab")


def tcpdump_binary() -> str:
    return _lab_binary("tcpdump", "tcpdump-lab")


def _signal_all(sig: int) -> list[str]:
    """Send `sig` to every process living in the lab namespaces; return pids we could not signal."""
    failed: list[str] = []
    for name in NAMESPACES.values():
        for pid in _run(["ip", "netns", "pids", name], check=False).stdout.split():
            try:
                os.kill(int(pid), sig)
            except ProcessLookupError:
                pass
            except (PermissionError, ValueError):
                failed.append(pid)
    return failed
''')

# 2) down() must not crash when a process cannot be signalled
start = text.index("def down(quiet: bool = False) -> None:")
end = text.index("# -------------------------------------------------- network conditions (F7) --")
text = text[:start] + '''def down(quiet: bool = False) -> None:
    require_root()
    _signal_all(signal.SIGTERM)
    time.sleep(0.3)
    stuck = _signal_all(signal.SIGKILL)
    for name in NAMESPACES.values():
        _run(["ip", "netns", "del", name], check=False)
    if stuck and not quiet:
        print(f"[lab] WARNING: could not stop process(es) {sorted(set(stuck))}: a security profile "
              "(AppArmor) is protecting them. Reboot the VM once to clear them.")
    if not quiet:
        print("[lab] stopped; namespaces removed (logs kept in /tmp/dnslab)")


''' + text[end:]

# 3) the capture uses the unconfined tcpdump and stops safely
replace('''in_ns("client", ["tcpdump", "-i", self.iface,''', '''in_ns("client", [tcpdump_binary(), "-i", self.iface,''')
replace('''            time.sleep(0.4)                       # let the last packets arrive
            self.proc.send_signal(signal.SIGINT)
''', '''            time.sleep(0.4)                       # let the last packets arrive
            try:
                self.proc.send_signal(signal.SIGINT)
            except PermissionError as exc:
                self.proc = None
                raise LabError("cannot stop tcpdump (permission denied, AppArmor?): reboot the VM "
                               "once, then run again") from exc
''')
path.write_text(text)
print("patched src/dns_analyzer/lab.py")