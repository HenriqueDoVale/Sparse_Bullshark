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

def read_nodes(n_nodes: int | None):
    """Read all rows from nodes_distributed.csv, truncating to n_nodes if specified."""
    rows = []
    with open(NODES_CSV, newline="") as f:
        for row in csv.DictReader(f):
            rows.append({
                "id":       int(row["id"]),
                "host":     row["host"].strip(),
                "port":     row.get("port", "").strip(),
                "behavior": row.get("behavior", "ok").strip(),
            })
    if n_nodes is not None:
        rows = rows[:n_nodes]
    return rows


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

def build_remote_script(node_ids, all_nodes, priv_keys, tx_size, n_tx, mode, input_rate, rbc, no_prbc_sigs, reduced_quorum, decoupled, wan_delay, recovery_timeout_ms):
    """Build a bash script that runs all assigned nodes on one machine."""
    # Build the CSV content for the active subset of nodes so the binary sees
    # only the N nodes participating in this run (not the full 50-node file).
    csv_lines = ["id,host,port,behavior"]
    for n in all_nodes:
        csv_lines.append(f"{n['id']},{n['host']},{n['port']},{n['behavior']}")
    csv_content = "\\n".join(csv_lines)

    lines = [
        "#!/bin/bash",
        f"cd {WORK_DIR}",
        # The binary reads ./shared/nodes.csv (hardcoded, see
        # shared/src/initializer.rs). Writing to nodes_distributed.csv here
        # instead would be silently inert — this must overwrite the file the
        # binary actually loads on every run.
        f"printf '{csv_content}\\n' > shared/nodes.csv",
        f"export PROTOCOL={mode}",
        "export RUST_LOG=warn",
    ]

    # WAN emulation: inject one-way latency via tc netem on every outgoing packet.
    # RTT ≈ 2 × wan_delay because both endpoints apply the delay symmetrically.
    if wan_delay > 0:
        lines += [
            "",
            "# WAN emulation — inject artificial latency on all outgoing packets",
            "IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)",
            "sudo tc qdisc del dev \"$IFACE\" root 2>/dev/null || true",
            f"sudo tc qdisc add dev \"$IFACE\" root netem delay {wan_delay}ms",
        ]
    if input_rate > 0:
        lines.append(f"export INPUT_RATE={input_rate}")
    if mode == "sailfish":
        lines.append(f"export RBC_MODE={rbc}")
    if mode == "prbc_sailfish" and no_prbc_sigs:
        lines.append("export PRBC_SIGS=off")
    if mode == "prbc_sailfish" and reduced_quorum:
        lines.append("export REDUCED_QUORUM=on")
    if decoupled:
        lines.append("export MEMPOOL_MODE=decoupled")
    if recovery_timeout_ms is not None:
        lines.append(f"export RECOVERY_TIMEOUT_MS={recovery_timeout_ms}")

    for nid in node_ids:
        # Single-quote the key: base64 chars never contain single quotes
        lines.append(f"export PRIVATE_KEY_{nid}='{priv_keys[nid]}'")

    lines += [
        "",
        "# Kill any leftover processes from a previous run",
        "pkill -9 -f sparse_bullshark 2>/dev/null || true",
        "sleep 3",
        "",
        "pids=()",
    ]

    for nid in node_ids:
        lines.append(
            f"{BINARY} {nid} {tx_size} {n_tx} "
            f">/tmp/sb_{nid}.out 2>/tmp/sb_{nid}.err & pids+=($!)"
        )

    cleanup = ["", 'for pid in "${pids[@]}"; do wait "$pid"; done']
    if wan_delay > 0:
        cleanup += [
            "",
            "# Remove tc rule after the run",
            "sudo tc qdisc del dev \"$IFACE\" root 2>/dev/null || true",
        ]
    cleanup += ["", "# Output each node's results with a clear separator"]
    lines += cleanup
    for nid in node_ids:
        lines.append(f'echo "__SB_NODE_{nid}_START__"')
        lines.append(f"cat /tmp/sb_{nid}.out")
        lines.append(f'echo "__SB_NODE_{nid}_END__"')
        # The binary's own warn!/error! output goes to this file (stdout is
        # reserved for the CONFIG/RESULTS block) — retrieve it too, or every
        # warn! this run produced is silently stranded on the remote machine.
        lines.append(f'echo "__SB_NODE_{nid}_ERR_START__"')
        lines.append(f"cat /tmp/sb_{nid}.err")
        lines.append(f'echo "__SB_NODE_{nid}_ERR_END__"')

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
    """Split the concatenated machine output into (node_id, block) pairs."""
    matches = re.findall(r'__SB_NODE_(\d+)_START__\n(.*?)__SB_NODE_\d+_END__',
                        combined, re.DOTALL)
    return [(int(nid), b.strip()) for nid, b in matches if b.strip()]


def split_node_err_outputs(combined):
    """Split out each node's own warn!/error! log (its stderr file, cat'd back
    separately from stdout — see build_remote_script). Only non-empty logs."""
    matches = re.findall(r'__SB_NODE_(\d+)_ERR_START__\n(.*?)__SB_NODE_\d+_ERR_END__',
                        combined, re.DOTALL)
    return [(int(nid), b.strip()) for nid, b in matches if b.strip()]


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
    parser.add_argument("--n-nodes",      type=int, default=None,
                        help="Node count; selects nodes_distributed_N.csv on the cluster "
                             "(omit to use nodes_distributed.csv)")
    parser.add_argument("--input-rate",   type=int, default=0, help="Aggregate tx/s (0 = unlimited)")
    parser.add_argument("--rbc",          choices=["bracha", "signed_vote"], default="bracha",
                        help="RBC variant for sailfish mode")
    parser.add_argument("--no-prbc-sigs", action="store_true")
    parser.add_argument("--reduced-quorum", action="store_true",
                        help="Use f+1 quorum instead of 2f+1 (CFT threshold, not BFT-safe)")
    parser.add_argument("--decoupled",    action="store_true",
                        help="Enable MEMPOOL_MODE=decoupled (Narwhal-style batch store)")
    parser.add_argument("--wan-delay",    type=int, default=0, metavar="MS",
                        help="One-way WAN latency to inject via tc netem (ms). RTT ≈ 2×value. "
                             "0 = no delay (LAN). Example: --wan-delay 50 → 100ms RTT")
    parser.add_argument("--recovery-timeout-ms", type=int, default=None, metavar="MS",
                        help="Override RECOVERY_TIMEOUT_MS on all cluster nodes "
                             "(binary default: 500ms). Set very low (e.g. 5) to force "
                             "Phase-3 recovery to escalate to the network instead of "
                             "resolving locally, for testing the recovery path itself.")
    parser.add_argument("--logs",         action="store_true", help="Print stderr from each machine")
    args = parser.parse_args()

    # Load cluster topology
    nodes     = read_nodes(args.n_nodes)
    priv_keys = read_private_keys()
    groups    = group_by_host(nodes)   # {ip: [node_ids]}

    if len(priv_keys) < len(nodes):
        print(f"Error: keys file has {len(priv_keys)} keys but {len(nodes)} nodes configured.",
              file=sys.stderr)
        sys.exit(1)

    print("--------------------------------------------------")
    print(" STARTING DISTRIBUTED EXPERIMENT")
    print("--------------------------------------------------")
    rbc_suffix     = f" [{args.rbc}]" if args.mode == "sailfish" else ""
    quorum_suffix  = " [quorum: f+1]" if (args.mode == "prbc_sailfish" and args.reduced_quorum) else ""
    mempool_suffix = " [decoupled]" if args.decoupled else ""
    wan_suffix     = f" [WAN {args.wan_delay}ms one-way / {args.wan_delay*2}ms RTT]" if args.wan_delay > 0 else ""
    recovery_suffix = f" [recovery timeout: {args.recovery_timeout_ms}ms]" if args.recovery_timeout_ms is not None else ""
    print(f"  Protocol:   {args.mode.replace('_', '-').upper()}{rbc_suffix}{quorum_suffix}{mempool_suffix}{wan_suffix}{recovery_suffix}")
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
            node_ids, nodes, priv_keys, args.tx_size, args.n_tx,
            args.mode, args.input_rate, args.rbc, args.no_prbc_sigs, args.reduced_quorum,
            args.decoupled, args.wan_delay, args.recovery_timeout_ms,
        )
        machine_order.append((ip, node_ids))
        tasks.append(asyncio.create_task(run_on_machine(ip, script, timeout_secs)))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Parse results
    all_configs, all_results, all_node_ids = [], [], []
    all_stderr = {}
    node_binary_logs = {}

    for (ip, node_ids), result in zip(machine_order, raw_results):
        if isinstance(result, Exception):
            print(f"Warning: {ip} raised exception: {result}", file=sys.stderr)
            continue

        stdout, stderr, rc = result
        all_stderr[ip] = stderr

        if rc != 0:
            print(f"Warning: {ip} exited with code {rc}", file=sys.stderr)

        for nid, err in split_node_err_outputs(stdout):
            node_binary_logs[nid] = err

        node_blocks = split_node_outputs(stdout)
        if not node_blocks:
            print(f"Warning: {ip} produced no parseable output.", file=sys.stderr)
            print(f"  Last stderr: {stderr.splitlines()[-5:] if stderr else '(empty)'}", file=sys.stderr)
            continue

        for nid, block in node_blocks:
            cfg, res = parse_block(block)
            if cfg and res:
                all_configs.append(cfg)
                all_results.append(res)
                all_node_ids.append(nid)
            else:
                print(f"Warning: node {nid} on {ip} produced incomplete output.", file=sys.stderr)

    if not all_results:
        print("No results to display — all nodes failed or produced no output.", file=sys.stderr)
        print("Run with --logs to see stderr from each machine.", file=sys.stderr)
        sys.exit(1)

    print_summary(all_configs[0], compute_median(all_results), len(all_results))

    # Recovery counters are often concentrated on one or two nodes (e.g. the
    # peers a Byz1 proposer excludes) — the median across all nodes can then
    # read as ~0 even when a real, nonzero number of events happened
    # somewhere. --logs breaks that out per node so it's not hidden.
    if args.logs:
        cols = ["Payload-lag events", "Network recoveries", "Recovery resp OK", "Recovery resp served"]
        if any(c in all_results[0] for c in cols):
            print("--------------------------------------------------")
            print(" PER-NODE RECOVERY COUNTERS")
            print("--------------------------------------------------")
            print(f"{'Node':>6}  " + "  ".join(f"{c:>20}" for c in cols))
            for nid, res in sorted(zip(all_node_ids, all_results)):
                print(f"{nid:>6}  " + "  ".join(f"{res.get(c, '-'):>20}" for c in cols))
            print()

    if args.logs:
        print("--------------------------------------------------")
        print(" PER-NODE BINARY LOGS (warn!/error!)")
        print("--------------------------------------------------")
        if node_binary_logs:
            for nid in sorted(node_binary_logs):
                print(f"\n--- Node {nid} ---")
                print(node_binary_logs[nid])
        else:
            print("(none — no node produced any warn!/error! output)")

        print("\n--------------------------------------------------")
        print(" SSH/BASH SESSION STDERR (script-level errors, not the binary's own logs)")
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
