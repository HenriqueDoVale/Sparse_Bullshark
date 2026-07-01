#!/usr/bin/env python3
"""
bench.py — Automated benchmark suite for sparse-bullshark protocols.

Edit EXPERIMENTS and OPTIONS below, then run:
    python3 bench.py

The script regenerates shared/nodes.csv before each run, calls run_linux.py,
and prints a comparison table at the end with per-label medians.
"""

import csv
import os
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict


# ═══════════════════════════════════════════════════════════════════════════════
#  USER CONFIGURATION — edit this section
# ═══════════════════════════════════════════════════════════════════════════════

EXPERIMENTS = [
    # Each dict is one run executed in the order listed.
    #
    # Fields:
    #   n_nodes      — committee size (nodes.csv is regenerated automatically)
    #   tx_size      — transaction size in bytes
    #   n_tx         — transactions per block
    #   mode         — "sailfish" | "prbc_sailfish"
    #   rbc          — "bracha" | "signed_vote"  (ignored for prbc_sailfish)
    #   no_prbc_sigs — True = disable Ed25519 vote sigs in PRBC (ignored for sailfish)
    #   input_rate   — tx/s cap; 0 = unlimited
    #   timeout_ms   — round timeout in milliseconds
    #   label        — short name shown in the results table

    # ── n=10, 3 interleaved pairs ────────────────────────────────────────────
    {"n_nodes": 10, "tx_size": 512, "n_tx": 500, "mode": "sailfish",      "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "Bracha n=10"},
    {"n_nodes": 10, "tx_size": 512, "n_tx": 500, "mode": "prbc_sailfish", "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "PRBC   n=10"},
    {"n_nodes": 10, "tx_size": 512, "n_tx": 500, "mode": "sailfish",      "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "Bracha n=10"},
    {"n_nodes": 10, "tx_size": 512, "n_tx": 500, "mode": "prbc_sailfish", "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "PRBC   n=10"},
    {"n_nodes": 10, "tx_size": 512, "n_tx": 500, "mode": "sailfish",      "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "Bracha n=10"},
    {"n_nodes": 10, "tx_size": 512, "n_tx": 500, "mode": "prbc_sailfish", "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "PRBC   n=10"},

    # ── n=15, 3 interleaved pairs ────────────────────────────────────────────
    {"n_nodes": 15, "tx_size": 512, "n_tx": 500, "mode": "sailfish",      "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "Bracha n=15"},
    {"n_nodes": 15, "tx_size": 512, "n_tx": 500, "mode": "prbc_sailfish", "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "PRBC   n=15"},
    {"n_nodes": 15, "tx_size": 512, "n_tx": 500, "mode": "sailfish",      "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "Bracha n=15"},
    {"n_nodes": 15, "tx_size": 512, "n_tx": 500, "mode": "prbc_sailfish", "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "PRBC   n=15"},
    {"n_nodes": 15, "tx_size": 512, "n_tx": 500, "mode": "sailfish",      "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "Bracha n=15"},
    {"n_nodes": 15, "tx_size": 512, "n_tx": 500, "mode": "prbc_sailfish", "rbc": "bracha", "no_prbc_sigs": False, "input_rate": 0, "timeout_ms": 500, "label": "PRBC   n=15"},
]

# Network settings used when regenerating nodes.csv
BASE_PORT = 8000
HOST      = "127.0.0.1"

# ═══════════════════════════════════════════════════════════════════════════════


NODES_CSV  = "./shared/nodes.csv"
KEYS_FILE  = "./keys"


# ── Helpers ───────────────────────────────────────────────────────────────────

def count_keys():
    try:
        with open(KEYS_FILE) as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return 0


def write_nodes_csv(n):
    os.makedirs(os.path.dirname(NODES_CSV), exist_ok=True)
    with open(NODES_CSV, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "host", "port", "behavior"])
        for i in range(n):
            w.writerow([i, HOST, BASE_PORT + i, "ok"])


def build_cmd(exp):
    cmd = [
        sys.executable, "run_linux.py",
        "--tx-size", str(exp["tx_size"]),
        "--n-tx",    str(exp["n_tx"]),
        "--mode",    exp["mode"],
        "--timeout", str(exp["timeout_ms"]),
    ]
    if exp.get("input_rate", 0) > 0:
        cmd += ["--input-rate", str(exp["input_rate"])]
    if exp["mode"] == "sailfish":
        cmd += ["--rbc", exp.get("rbc", "bracha")]
    if exp["mode"] == "prbc_sailfish" and exp.get("no_prbc_sigs"):
        cmd.append("--no-prbc-sigs")
    return cmd


def parse_section(output, section_marker):
    """Return a dict of key→value from a CONFIG or RESULTS block."""
    result  = {}
    active  = False
    for line in output.splitlines():
        if section_marker in line:
            active = True
            continue
        if active:
            if line.startswith("+ "):   # next section started
                break
            m = re.match(r"  (.+?):\s{2,}(.+)", line)
            if m:
                result[m.group(1).strip()] = m.group(2).strip()
    return result


def extract_num(s):
    """Return the leading float from a result string, e.g. '95233 tx/s' → 95233.0."""
    m = re.match(r"^([\d.]+)", s.replace(",", ""))
    return float(m.group(1)) if m else None


def fmt_int(n):
    return f"{int(round(n)):,}" if n is not None else "—"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    n_keys    = count_keys()
    max_nodes = max(e["n_nodes"] for e in EXPERIMENTS)

    if n_keys < max_nodes:
        print(f"Error: keys file has {n_keys} entries but max n_nodes={max_nodes}.",
              file=sys.stderr)
        print("Generate more keys with setup_keys.sh before running.", file=sys.stderr)
        sys.exit(1)

    print(f"Benchmark: {len(EXPERIMENTS)} run(s), max committee={max_nodes}")
    print(f"Keys available: {n_keys}")

    rows = []   # list of (label, n_nodes, config_dict, results_dict, ok)
    total = len(EXPERIMENTS)

    for idx, exp in enumerate(EXPERIMENTS, 1):
        label   = exp["label"]
        n_nodes = exp["n_nodes"]

        print(f"\n{'═'*62}")
        print(f"  Run {idx}/{total}: {label}  "
              f"(n={n_nodes}, {exp['tx_size']}B×{exp['n_tx']})")
        print(f"{'═'*62}")

        write_nodes_csv(n_nodes)
        cmd = build_cmd(exp)

        t0   = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True)
        wall = time.time() - t0

        if proc.returncode != 0:
            print(f"  FAILED (exit {proc.returncode})", file=sys.stderr)
            # Show last few lines of stderr to help diagnose
            for line in proc.stderr.strip().splitlines()[-10:]:
                print(f"  {line}", file=sys.stderr)
            rows.append((label, n_nodes, {}, {}, False))
            continue

        # Pass through the formatted output run_linux.py already produced
        print(proc.stdout)
        print(f"  Wall time: {wall:.0f}s")

        cfg = parse_section(proc.stdout, "+ CONFIG:")
        res = parse_section(proc.stdout, "+ RESULTS:")
        rows.append((label, n_nodes, cfg, res, True))

    # ── Summary table ─────────────────────────────────────────────────────────
    W = 72
    print(f"\n{'═'*W}")
    print(f"  BENCHMARK SUMMARY — all {total} run(s)")
    print(f"{'═'*W}")
    print(f"  {'#':>3}  {'Label':<18} {'N':>4}  "
          f"{'TPS':>10}  {'Latency':>10}  {'Rounds/s':>9}  Status")
    print(f"  {'─'*65}")

    by_label = defaultdict(list)

    for i, (label, n_nodes, cfg, res, ok) in enumerate(rows, 1):
        if ok:
            tps  = fmt_int(extract_num(res.get("Consensus TPS", "")))
            lat  = res.get("Consensus latency", "—")
            rps  = res.get("Rounds/s", "—")
            status = "OK"
            v = extract_num(res.get("Consensus TPS", ""))
            if v is not None:
                by_label[label].append(v)
        else:
            tps = lat = rps = "—"
            status = "FAILED"

        print(f"  {i:>3}  {label:<18} {n_nodes:>4}  "
              f"{tps:>10}  {lat:>10}  {rps:>9}  {status}")

    print(f"{'═'*W}")

    if by_label:
        print()
        print(f"  Median Consensus TPS per label  ({len(rows)} total run(s)):")
        print(f"  {'─'*45}")
        for label, vals in by_label.items():
            med = statistics.median(vals)
            print(f"    {label:<18}  {fmt_int(med):>10} tx/s  "
                  f"(median of {len(vals)} run{'s' if len(vals) != 1 else ''})")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)