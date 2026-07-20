#!/usr/bin/env python3
"""
run_distributed.py — Run a sparse-bullshark experiment across a GCP cluster.

Reads shared/nodes_distributed.csv to determine the cluster topology, SSHes into
each machine via gcloud compute ssh, runs the assigned nodes concurrently, and
prints a single aggregated RESULTS block (median across all nodes).

Usage (same flags as run_linux.py):
    python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish --input-rate 50000
    python3 run_distributed.py --tx-size 512 --n-tx 500 --mode sailfish
    python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish
"""

import argparse
import asyncio
import csv
import os
import re
import statistics
import sys
from collections import defaultdict

# ── Cluster config ─────────────────────────────────────────────────────────────

KEYS_FILE  = "./keys"
NODES_CSV  = "./shared/nodes_distributed.csv"
WORK_DIR   = "~/Sparse_Bullshark"
BINARY     = "./target/release/sparse_bullshark"
SSH_USER   = "henriquecostavale"
SSH_KEY    = os.path.expanduser("~/.ssh/google_compute_engine")
SSH_OPTS   = ["-i", SSH_KEY, "-o", "StrictHostKeyChecking=no", "-o", "LogLevel=ERROR"]

# ── File readers ───────────────────────────────────────────────────────────────

def read_nodes():
    nodes = []
    with open(NODES_CSV, newline="") as f:
        for row in csv.DictReader(f):
            nodes.append({"id": int(row["id"]), "host": row["host"].strip()})
    return nodes


def read_private_keys():
    keys = []
    with open(KEYS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                private, _ = line.split(":", 1)
                keys.append(private)
    return keys


def group_by_host(nodes):
    groups = defaultdict(list)
    for n in nodes:
        groups[n["host"]].append(n["id"])
    return dict(groups)


# ── Remote script builder ──────────────────────────────────────────────────────

def build_remote_script(node_ids, priv_keys, tx_size, n_tx, mode, input_rate, rbc, no_prbc_sigs, reduced_quorum):
    """Build a bash script that runs all assigned nodes on one machine."""
    lines = [
        "#!/bin/bash",
        f"cd {WORK_DIR}",
        f"export PROTOCOL={mode}",
        "export RUST_LOG=warn",
    ]
    if input_rate > 0:
        lines.append(f"export INPUT_RATE={input_rate}")
    if mode == "sailfish":
        lines.append(f"export RBC_MODE={rbc}")
    if mode == "prbc_sailfish" and no_prbc_sigs:
        lines.append("export PRBC_SIGS=off")
    if mode == "prbc_sailfish" and reduced_quorum:
        lines.append("export REDUCED_QUORUM=on")

    for nid in node_ids:
        # Single-quote the key: base64 chars never contain single quotes
        lines.append(f"export PRIVATE_KEY_{nid}='{priv_keys[nid]}'")

    lines += [
        "",
        "# Kill any leftover processes from a previous run",
        "pkill -f sparse_bullshark 2>/dev/null || true",
        "sleep 1",
        "",
        "pids=()",
    ]

    for nid in node_ids:
        lines.append(
            f"{BINARY} {nid} {tx_size} {n_tx} "
            f">/tmp/sb_{nid}.out 2>/tmp/sb_{nid}.err & pids+=($!)"
        )

    lines += [
        "",
        'for pid in "${pids[@]}"; do wait "$pid"; done',
        "",
        "# Output each node's results with a clear separator",
    ]
    for nid in node_ids:
        lines.append(f'echo "__SB_NODE_{nid}_START__"')
        lines.append(f"cat /tmp/sb_{nid}.out")
        lines.append(f'echo "__SB_NODE_{nid}_END__"')

    return "\n".join(lines)


# ── SSH runner ─────────────────────────────────────────────────────────────────

async def run_on_machine(ip, script, timeout_secs):
    """SSH into a machine by internal IP and run script via stdin."""
    proc = await asyncio.create_subprocess_exec(
        "ssh", *SSH_OPTS, f"{SSH_USER}@{ip}", "bash", "-s",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=script.encode()),
            timeout=timeout_secs,
        )
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except OSError:
            pass
        return "", f"[{ip}] timed out after {timeout_secs}s\n", -1


# ── Output parsing ─────────────────────────────────────────────────────────────

def split_node_outputs(combined):
    """Split the concatenated machine output into individual node blocks."""
    blocks = re.findall(r'__SB_NODE_\d+_START__\n(.*?)__SB_NODE_\d+_END__',
                        combined, re.DOTALL)
    return [b.strip() for b in blocks if b.strip()]


def parse_block(output):
    config, results = {}, {}
    section = None
    for line in output.splitlines():
        if "+ CONFIG:" in line:
            section = "config"
        elif "+ RESULTS:" in line:
            section = "results"
        elif section:
            m = re.match(r'  (.+?):\s{2,}(.+)', line)
            if m:
                key = m.group(1).strip()
                val = m.group(2).strip()
                (config if section == "config" else results)[key] = val
    return config, results


def compute_median(all_results):
    out = {}
    for key in all_results[0]:
        nums, unit = [], ""
        for r in all_results:
            v = r.get(key, "")
            m = re.match(r'^([\d.]+)\s*(.*)', v)
            if m:
                nums.append(float(m.group(1)))
                unit = m.group(2).strip()
        if nums:
            med = statistics.median(nums)
            sample = all_results[0][key].split()[0]
            fmt = f"{med:.1f}" if "." in sample else f"{int(round(med))}"
            out[key] = f"{fmt} {unit}".strip() if unit else fmt
        else:
            out[key] = all_results[0].get(key, "")
    return out


def print_summary(config, results, n_nodes):
    w = 24
    print()
    print(f"(Median of {n_nodes} node(s))")
    print()
    print("+ CONFIG:")
    for k, v in config.items():
        print(f"  {(k + ':'):<{w}} {v}")
    print()
    print("+ RESULTS:")
    for k, v in results.items():
        print(f"  {(k + ':'):<{w}} {v}")
    print()


# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Run sparse-bullshark on a GCP cluster")
    parser.add_argument("--tx-size",      type=int, required=True, help="Transaction size in bytes")
    parser.add_argument("--n-tx",         type=int, required=True, help="Transactions per block")
    parser.add_argument("--mode",         choices=["sailfish", "prbc_sailfish"], default="prbc_sailfish")
    parser.add_argument("--input-rate",   type=int, default=0, help="Aggregate tx/s (0 = unlimited)")
    parser.add_argument("--rbc",          choices=["bracha", "signed_vote"], default="bracha",
                        help="RBC variant for sailfish mode")
    parser.add_argument("--no-prbc-sigs", action="store_true")
    parser.add_argument("--reduced-quorum", action="store_true",
                        help="Use f+1 quorum instead of 2f+1 (CFT threshold, not BFT-safe)")
    parser.add_argument("--logs",         action="store_true", help="Print stderr from each machine")
    args = parser.parse_args()

    # Load cluster topology
    nodes     = read_nodes()
    priv_keys = read_private_keys()
    groups    = group_by_host(nodes)   # {ip: [node_ids]}

    if len(priv_keys) < len(nodes):
        print(f"Error: keys file has {len(priv_keys)} keys but {len(nodes)} nodes configured.",
              file=sys.stderr)
        sys.exit(1)

    print("--------------------------------------------------")
    print(" STARTING DISTRIBUTED EXPERIMENT")
    print("--------------------------------------------------")
    rbc_suffix = f" [{args.rbc}]" if args.mode == "sailfish" else ""
    quorum_suffix = " [quorum: f+1]" if (args.mode == "prbc_sailfish" and args.reduced_quorum) else ""
    print(f"  Protocol:   {args.mode.replace('_', '-').upper()}{rbc_suffix}{quorum_suffix}")
    print(f"  Tx size:    {args.tx_size} B")
    print(f"  Tx/block:   {args.n_tx}")
    print(f"  Nodes:      {len(nodes)}")
    print(f"  Machines:   {len(groups)}")
    print(f"  Input rate: {'unlimited' if args.input_rate == 0 else str(args.input_rate) + ' tx/s'}")
    print("--------------------------------------------------")
    print("Running... (waiting for all machines to finish)")

    # Generous timeout: execution time (~60s) + startup + SSH overhead
    timeout_secs = 180

    # Launch all machines concurrently
    machine_order = []
    tasks = []
    for ip, node_ids in groups.items():
        script = build_remote_script(
            node_ids, priv_keys, args.tx_size, args.n_tx,
            args.mode, args.input_rate, args.rbc, args.no_prbc_sigs, args.reduced_quorum,
        )
        machine_order.append((ip, node_ids))
        tasks.append(asyncio.create_task(run_on_machine(ip, script, timeout_secs)))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Parse results
    all_configs, all_results = [], []
    all_stderr = {}

    for (ip, node_ids), result in zip(machine_order, raw_results):
        if isinstance(result, Exception):
            print(f"Warning: {ip} raised exception: {result}", file=sys.stderr)
            continue

        stdout, stderr, rc = result
        all_stderr[ip] = stderr

        if rc != 0:
            print(f"Warning: {ip} exited with code {rc}", file=sys.stderr)

        node_blocks = split_node_outputs(stdout)
        if not node_blocks:
            print(f"Warning: {ip} produced no parseable output.", file=sys.stderr)
            print(f"  Last stderr: {stderr.splitlines()[-5:] if stderr else '(empty)'}", file=sys.stderr)
            continue

        for block in node_blocks:
            cfg, res = parse_block(block)
            if cfg and res:
                all_configs.append(cfg)
                all_results.append(res)
            else:
                print(f"Warning: a node on {ip} produced incomplete output.", file=sys.stderr)

    if not all_results:
        print("No results to display — all nodes failed or produced no output.", file=sys.stderr)
        print("Run with --logs to see stderr from each machine.", file=sys.stderr)
        sys.exit(1)

    print_summary(all_configs[0], compute_median(all_results), len(all_results))

    if args.logs:
        print("--------------------------------------------------")
        print(" MACHINE LOGS (stderr)")
        print("--------------------------------------------------")
        for ip, stderr in all_stderr.items():
            if stderr.strip():
                print(f"\n--- {ip} ---")
                print(stderr)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
