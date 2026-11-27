#!/usr/bin/env bash
# setup.sh - one-time preparation of the lab on Ubuntu 24.04.
# Run as your NORMAL user (it asks for sudo only where needed):   bash scripts/setup.sh
set -uo pipefail
cd "$(dirname "$0")/.."

echo "== 1. checking required programs =="
missing=0
for tool in ip tc dig tcpdump openssl named named-checkconf named-checkzone rndc rndc-confgen; do
    if command -v "$tool" >/dev/null || [[ -x /usr/sbin/$tool ]]; then
        echo "  ok       $tool"
    else
        echo "  MISSING  $tool"; missing=1
    fi
done
if [[ $missing -eq 1 ]]; then
    echo
    echo "Install the missing programs with:"
    echo "  sudo apt install bind9 bind9-utils bind9-dnsutils iproute2 tcpdump openssl"
    exit 1
fi
echo "  (optional, only for manual packet analysis: sudo apt install tshark wireshark)"

echo "== 2. BIND9 must support DoT and DoH (needs libnghttp2) =="
if /usr/sbin/named -V 2>&1 | grep -q "libnghttp2"; then echo "  ok"; else echo "  WARNING: this BIND build has no nghttp2 -> DoH will not work"; fi

echo "== 3. traffic shaping (tc netem) =="
if sudo modprobe sch_netem && sudo tc qdisc add dev lo root netem delay 1ms 2>/dev/null; then
    sudo tc qdisc del dev lo root; echo "  ok: netem works"
else
    echo "  WARNING: netem not available. Try: sudo apt install linux-modules-extra-\$(uname -r) && sudo modprobe sch_netem"
fi

echo "== 4. unconfined copy of named (Ubuntu's AppArmor blocks /usr/sbin/named from reading project files) =="
sudo install -m 755 /usr/sbin/named /usr/local/sbin/named-lab && echo "  installed /usr/local/sbin/named-lab"

echo "== 5. validating the zone files =="
named-checkzone . configs/bind/zones/root.zone >/dev/null && echo "  ok  root.zone"
named-checkzone test configs/bind/zones/test.zone >/dev/null && echo "  ok  test.zone"
named-checkzone example.test configs/bind/zones/example.test.zone >/dev/null && echo "  ok  example.test.zone"

echo "== 6. TLS certificates (private CA + resolver certificate) =="
bash scripts/make_certs.sh

echo "== 7. Python packages =="
if [[ -x .venv/bin/pip ]]; then .venv/bin/pip install -q -r requirements.txt && echo "  ok"; else echo "  (no .venv found: create one with  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"; fi

echo
echo "Setup finished. Next:"
echo "  sudo .venv/bin/python analyzer.py lab up"
echo "  sudo .venv/bin/python analyzer.py iterative www.example.test --lab"
