#!/usr/bin/env python3
"""
topology.py - Build / stop / inspect the virtual testbed.

  sudo .venv/bin/python network/topology.py up
  sudo .venv/bin/python network/topology.py status
  sudo .venv/bin/python network/topology.py netem poor     (good | moderate | poor | clear)
  sudo .venv/bin/python network/topology.py down

This is a thin wrapper: the real work is in src/dns_analyzer/lab.py (also
available as `python analyzer.py lab ...`).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import analyzer  # noqa: E402

if __name__ == "__main__":
    sys.exit(analyzer.main(["lab", *sys.argv[1:]]))
