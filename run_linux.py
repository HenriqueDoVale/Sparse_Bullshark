#!/usr/bin/env python3
"""
run_linux.py — Linux equivalent of run_sparse.ps1

Starts all nodes concurrently, suppresses per-node output, and prints a
single CONFIG + RESULTS block with the median value of each metric.

Usage:
    python3 run_linux.py --tx-size 512 --n-tx 300 --mode prbc_sailfish
    python3 run_linux.py --tx-size 512 --n-tx 1000 --mode sailfish
    python3 run_linux.py --tx-size 512 --n-tx 300 --mode prbc_sailfish --input-rate 50000
"""

import argparse
import asyncio
import csv
import os
import re
import socket
import statistics
import subprocess
import sys
import time


KEYS_FILE   = "./keys"
NODES_CSV   = "./shared/nodes.csv"
BINARY      = "./target/release/sparse_bullshark.exe" if sys.platform == "win32" else "./target/release/sparse_bullshark"
BINARY_NAME = os.path.basename(BINARY)


# ── File readers ──────────────────────────────────────────────────────────────

def read_nodes():
    nodes = []
    with open(NODES_CSV, newline="") as f:
        for row in csv.DictReader(f):
            nodes.append({
                "id":   int(row["id"]),
                "host": row["host"].strip(),
                "port": int(row["port"].strip()),
            })
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


# ── Cleanup ───────────────────────────────────────────────────────────────────

def port_free(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def cleanup_previous_run(nodes):
    """Kill any leftover experiment processes, then wait for all ports to free."""
    print("Cleaning up leftover processes...", end=" ", flush=True)

    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/IM", BINARY_NAME], capture_output=True)
    else:
        subprocess.run(["pkill", "-f", BINARY_NAME], capture_output=True)
        # pkill exits 1 when nothing matched — that is fine, we ignore the return code

    # Wait up to 5 s for all ports to become free
    ports = [(n["host"], n["port"]) for n in nodes]
    deadline = time.time() + 5
    while time.time() < deadline:
        busy = [(h, p) for h, p in ports if not port_free(h, p)]
        if not busy:
            print("OK")
            return
        time.sleep(0.2)

    busy = [(h, p) for h, p in ports if not port_free(h, p)]
    if busy:
        print(f"\nWarning: ports still occupied after cleanup: {busy}", file=sys.stderr)
        print("Try waiting a few seconds and running again.", file=sys.stderr)
    else:
        print("OK")


# ── Output parsing ────────────────────────────────────────────────────────────

def parse_block(output):
    """Extract CONFIG and RESULTS dicts from a node's captured output."""
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
                if section == "config":
                    config[key] = val
                else:
                    results[key] = val
    return config, results


def compute_median(all_results):
    """Return a results dict where each numeric field is replaced by its median."""
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
            sample_num = all_results[0][key].split()[0]
            fmt = f"{med:.1f}" if "." in sample_num else f"{int(round(med))}"
            out[key] = f"{fmt} {unit}".strip() if unit else fmt
        else:
            out[key] = all_results[0].get(key, "")
    return out


def print_summary(config, results, n_nodes):
    w = 24  # label column width (matches Rust output alignment)
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


# ── Node runner ───────────────────────────────────────────────────────────────

async def run_node(node_id, tx_size, n_tx, mode, input_rate, rbc, no_prbc_sigs, private_key,
                   stdout_buf, stderr_buf, procs):
    env = os.environ.copy()
    env[f"PRIVATE_KEY_{node_id}"] = private_key
    env["PROTOCOL"] = mode
    env["RUST_LOG"] = "warn"
    if input_rate > 0:
        env["INPUT_RATE"] = str(input_rate)
    if mode == "sailfish":
        env["RBC_MODE"] = rbc
    if mode == "prbc_sailfish" and no_prbc_sigs:
        env["PRBC_SIGS"] = "off"

    proc = await asyncio.create_subprocess_exec(
        BINARY, str(node_id), str(tx_size), str(n_tx),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    procs.append(proc)  # register so timeout handler can kill it

    async def drain(stream, buf):
        while True:
            line = await stream.readline()
            if not line:
                break
            buf.append(line.decode(errors="replace").rstrip())

    # stdout  = CONFIG+RESULTS (println!)
    # stderr  = log messages   (warn!, error!, info!)
    await asyncio.gather(drain(proc.stdout, stdout_buf), drain(proc.stderr, stderr_buf))
    await proc.wait()
    return proc.returncode


def kill_all(procs):
    """Kill every tracked subprocess (best-effort; ignores already-dead processes)."""
    for p in procs:
        try:
            p.kill()
        except (ProcessLookupError, OSError):
            pass


# ── Main ─────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(description="Run sparse-bullshark experiment on Linux")
    parser.add_argument("--tx-size",    type=int, required=True, help="Transaction size in bytes")
    parser.add_argument("--n-tx",       type=int, required=True, help="Transactions per block")
    parser.add_argument("--mode",       choices=["sailfish", "prbc_sailfish"], default="prbc_sailfish",
                        help="sailfish = Sailfish (Standard RBC), prbc_sailfish = PRBC-Sailfish")
    parser.add_argument("--input-rate", type=int, default=0,
                        help="Input rate in tx/s (0 = unlimited)")
    parser.add_argument("--rbc", choices=["bracha", "signed_vote"], default="bracha",
                        help="RBC variant for Sailfish (bracha or signed_vote; ignored for prbc_sailfish)")
    parser.add_argument("--no-prbc-sigs", action="store_true",
                        help="Disable Ed25519 vote signatures in PRBC-Sailfish (ignored for sailfish)")
    parser.add_argument("--logs", action="store_true",
                        help="Print captured stderr (warn/error logs) from each node after results")
    args = parser.parse_args()

    for path in [KEYS_FILE, NODES_CSV]:
        if not os.path.exists(path):
            print(f"Error: {path} not found.", file=sys.stderr)
            sys.exit(1)

    nodes     = read_nodes()
    priv_keys = read_private_keys()

    if len(priv_keys) < len(nodes):
        print(f"Error: keys file has {len(priv_keys)} entries but nodes.csv has {len(nodes)} nodes.",
              file=sys.stderr)
        sys.exit(1)

    # Kill leftover processes from any previous run, then verify ports are free
    cleanup_previous_run(nodes)

    # Compile once before starting nodes
    print("Building release binary...")
    result = subprocess.run(["cargo", "build", "--release"])
    if result.returncode != 0:
        print("Build failed.", file=sys.stderr)
        sys.exit(1)

    print("--------------------------------------------------")
    print(" STARTING EXPERIMENT")
    print("--------------------------------------------------")
    rbc_suffix = f" [{args.rbc}]" if args.mode == "sailfish" else ""
    print(f"  Protocol:   {args.mode.replace('_', '-').upper()}{rbc_suffix}")
    print(f"  Tx size:    {args.tx_size} B")
    print(f"  Tx/block:   {args.n_tx}")
    print(f"  Nodes:      {len(nodes)}")
    print(f"  Input rate: {'unlimited' if args.input_rate == 0 else str(args.input_rate) + ' tx/s'}")
    print("--------------------------------------------------")
    print("Running... (output suppressed, results printed on completion)")

    stdout_bufs = [[] for _ in nodes]
    stderr_bufs = [[] for _ in nodes]
    procs = []  # shared list; run_node appends each proc as it starts

    tasks = [
        asyncio.create_task(
            run_node(
                n["id"], args.tx_size, args.n_tx, args.mode,
                args.input_rate, args.rbc, args.no_prbc_sigs, priv_keys[n["id"]],
                stdout_bufs[i], stderr_bufs[i], procs
            )
        )
        for i, n in enumerate(nodes)
    ]

    # Hard timeout: EXECUTION_DURATION (60 s) + 60 s connection grace period.
    # If nodes are still stuck after this, something is wrong with the environment.
    timeout_secs = 120
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout_secs)
    except asyncio.TimeoutError:
        print(f"\nTimeout after {timeout_secs}s — nodes are stuck (connection or startup failure).",
              file=sys.stderr)
        for t in tasks:
            t.cancel()
        kill_all(procs)
        sys.exit(1)

    # Parse only stdout — CONFIG+RESULTS is always printed there via println!
    # stderr only contains log messages (warn!/error!) which we ignore unless debugging
    all_configs, all_results = [], []
    for i, buf in enumerate(stdout_bufs):
        cfg, res = parse_block("\n".join(buf))
        if cfg and res:
            all_configs.append(cfg)
            all_results.append(res)
        else:
            print(f"Warning: Node {nodes[i]['id']} produced no parseable output.", file=sys.stderr)
            print(f"  stdout: {buf[-5:] if buf else '(empty)'}", file=sys.stderr)
            print(f"  stderr: {stderr_bufs[i][-5:] if stderr_bufs[i] else '(empty)'}", file=sys.stderr)

    if not all_results:
        print("No results to display — all nodes failed or produced no output.", file=sys.stderr)
        print("Last stderr lines per node:", file=sys.stderr)
        for i, buf in enumerate(stderr_bufs):
            if buf:
                print(f"\n--- Node {nodes[i]['id']} stderr ---", file=sys.stderr)
                print("\n".join(buf[-20:]), file=sys.stderr)
        sys.exit(1)

    print_summary(all_configs[0], compute_median(all_results), len(all_results))

    if args.logs:
        print("--------------------------------------------------")
        print(" NODE LOGS (stderr)")
        print("--------------------------------------------------")
        for i, buf in enumerate(stderr_bufs):
            if buf:
                print(f"\n--- Node {nodes[i]['id']} ---")
                print("\n".join(buf))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(1)
