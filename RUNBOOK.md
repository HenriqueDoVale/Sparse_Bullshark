# Runbook — running PRBC-Sailfish and Narwhal Sailfish on the GCP cluster

For whoever is helping test this. Everything below runs from **node-0**, the
orchestrator machine. Sections marked ⚠️ **VERIFY** are things I could not
confirm directly — check them before relying on that part.

## Cluster facts

- 10 GCP VMs, `n2d-highcpu-8` (one, `10.164.0.6`, is `e2-highcpu-8` instead —
  slightly different/slower CPU platform, worth remembering if that machine's
  numbers look off).
- Internal IPs: `10.164.0.12` (node-0, the orchestrator), `.6`, `.11`, `.8`,
  `.9`, `.10`, `.13`, `.14`, `.15`, `.16`.
- SSH between machines: user `henriquecostavale`, key `~/.ssh/google_compute_engine`.
- Two separate codebases live on node-0:
  - **Our protocol** (PRBC-Sailfish / Sailfish): `~/Sparse_Bullshark`
  - **Narwhal Sailfish baseline**: `~/sailfish` (github.com/nibeshrestha/sailfish)

---

## Part A — Our protocol (PRBC-Sailfish / Sailfish)

### One-time / after any code change

```bash
cd ~/Sparse_Bullshark
git pull
bash setup_cluster.sh
```

This builds the release binary if it's missing, generates
`shared/nodes_distributed.csv`, and copies the binary + keys + config to all
10 machines.

> ⚠️ **VERIFY — node count per machine.** The committed `setup_cluster.sh` has
> `NODES_PER_MACHINE=5` at the top (→ 50 node slots, 5 per machine, assigned
> sequentially: machine 1 gets nodes 0–4, machine 2 gets 5–9, etc.). But
> earlier testing on this same cluster showed it behaving as **1 node per
> machine** after a VM reset — which doesn't match what's committed. Before
> trusting node-count/machine-mapping behavior, run on node-0:
> ```bash
> grep NODES_PER_MACHINE ~/Sparse_Bullshark/setup_cluster.sh
> ```
> and confirm what it currently says — it may have been hand-edited on the
> cluster and never committed back to git. If you need a specific total node
> count, edit that line and re-run `setup_cluster.sh`.

### Running a benchmark

```bash
python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish --n-nodes 10 --input-rate 20000
python3 run_distributed.py --tx-size 512 --n-tx 500 --mode sailfish --rbc signed_vote --n-nodes 10 --input-rate 10000
```

**Flags** (confirmed from `run_distributed.py --help` / source):

| Flag | Meaning |
|---|---|
| `--tx-size` (required) | bytes per transaction |
| `--n-tx` (required) | transactions per batch |
| `--mode` | `prbc_sailfish` (our protocol) or `sailfish` (baseline) |
| `--rbc` | `bracha` (default) or `signed_vote` — sailfish only |
| `--n-nodes N` | use only the first N rows of `nodes_distributed.csv` |
| `--input-rate` | aggregate tx/s cap; omit or 0 = unlimited (finds the ceiling) |
| `--decoupled` | sailfish only — digest-carrying vertices instead of inline payload |
| `--wan-delay MS` | inject one-way latency via `tc netem` on every machine, applied/cleaned up automatically (out of scope for this runbook) |
| `--reduced-quorum` | PRBC only — f+1 instead of 2f+1. **Not BFT-safe, experiments only** |
| `--no-prbc-sigs` | PRBC only — disable Ed25519 vote signatures |
| `--logs` | print stderr from every machine — use this if a run produces no results |

> FYI — the binary also reads `ROUND_TIMEOUT_MS`, `RECOVERY_TIMEOUT_MS`,
> `NETWORK_MBPS`, `CONSENSUS_NETWORK_PERCENT` as environment variables, but
> `run_distributed.py` does not forward any of these to the remote machines —
> setting them locally before running has no effect on the cluster. Not
> currently used for anything, so this is fine as-is. If that changes, they'd
> need to be added to `build_remote_script()` in `run_distributed.py` first.

### Changing which / how many nodes

- Total available nodes = whatever `setup_cluster.sh` generated into
  `shared/nodes_distributed.csv` (row count = `NODES_PER_MACHINE` × 10 —
  see the verify note above for what that currently is).
- `--n-nodes N` just takes the first N rows of that file.
- To change the total, edit `NODES_PER_MACHINE` in `setup_cluster.sh` and
  re-run it (regenerates the CSV and re-copies to every machine).

### If a run hangs / times out — manual cleanup

```bash
for h in 10.164.0.12 10.164.0.6 10.164.0.11 10.164.0.8 10.164.0.9 10.164.0.10 10.164.0.13 10.164.0.14 10.164.0.15 10.164.0.16; do
  ssh -i ~/.ssh/google_compute_engine -o StrictHostKeyChecking=no henriquecostavale@$h "pkill -9 -f sparse_bullshark" 2>/dev/null
done
```

---

## Part B — Narwhal Sailfish baseline

Location: `~/sailfish`, benchmark driver in `~/sailfish/benchmark`. This repo
has its **own** `setup_cluster.sh` inside `benchmark/` — separate from ours,
deploys to a different remote path (`~/sailfish_cluster/` on each machine, not
`~/Sparse_Bullshark`). Binaries are named `node` and `benchmark_client`.

### One-time / after any code change

```bash
cd ~/sailfish/benchmark
bash setup_cluster.sh
```

Builds `node` + `benchmark_client` in release mode and `scp`s them to
`~/sailfish_cluster/` on all 10 machines.

> ⚠️ **Kill leftover processes first, every time.** If a `node` or
> `benchmark_client` from a previous run is still executing on a machine, the
> `scp` overwrite fails outright (Linux won't let you overwrite a running
> binary) — this happened on **all 10 machines** in one observed run here,
> silently falling back to whatever binary was already deployed. The
> benchmark still produced results, just possibly with a stale binary. Kill
> first, then deploy:
> ```bash
> for h in 10.164.0.12 10.164.0.6 10.164.0.11 10.164.0.8 10.164.0.9 10.164.0.10 10.164.0.13 10.164.0.14 10.164.0.15 10.164.0.16; do
>   ssh -i ~/.ssh/google_compute_engine -o StrictHostKeyChecking=no $h "pkill -f node; pkill -f benchmark_client"
> done
> sleep 3
> bash setup_cluster.sh
> ```
> If you've changed Narwhal's Rust code and need to be sure it actually
> landed, spot-check a timestamp after deploying:
> ```bash
> ssh -i ~/.ssh/google_compute_engine henriquecostavale@10.164.0.6 "ls -la ~/sailfish_cluster/"
> ```

### Running a benchmark

```bash
cd ~/sailfish/benchmark
python3 run_cluster.py --topology topology_10.csv --workers 1 --tx-size 512 \
  --faults 0 --duration 60 --batch-size 512000 --max-batch-delay 50 --target-rate 20000
```

**Flags** (from `run_cluster.py --help`): `--topology`, `--workers`, `--faults`,
`--tx-size`, `--target-rate` (required, aggregate tx/s), `--duration`,
`--burst-ms`, `--batch-size`, `--max-batch-delay`, `--header-size`,
`--max-header-delay`, `--debug`. All but `--topology`, `--tx-size`,
`--target-rate`, `--duration` are optional — **confirmed defaults if
omitted**: `--batch-size` → 512,000 B, `--max-batch-delay` → **200 ms** (not
50 — the earlier n=10 workload-rate comparison explicitly passed `50`, so
don't compare those numbers against a default-flags run without noting the
difference).

Use `--workers 1` unless you're specifically pushing past ~20k tx/s — one
worker is enough at the rates this project tests.

### Changing node count

Node count = row count of the `--topology` CSV (`id,host` header, one row per
node, `host` = a machine's internal IP). **Confirmed working this session:**
`topology_10.csv` (10 nodes/10 machines), `topology_30.csv` (30 nodes/10
machines — 3/machine), `topology_50.csv` (50 nodes/10 machines — 5/machine) —
all produced real results. `topology_20.csv` exists but wasn't exercised
today; no reason to expect it's different, just noting it specifically wasn't
observed.

If you ever need a topology file for a node count that doesn't exist yet,
build it by round-robining IDs across the 10 machine IPs:
```text
id,host
0,10.164.0.12
1,10.164.0.6
2,10.164.0.11
3,10.164.0.8
4,10.164.0.9
5,10.164.0.10
6,10.164.0.13
7,10.164.0.14
8,10.164.0.15
9,10.164.0.16
10,10.164.0.12
11,10.164.0.6
... (continue wrapping)
```

### Cleanup between runs — do this every time

Narwhal's harness does **not** reliably kill nodes between runs; a stale
overlapping process gives silently wrong results.

```bash
for h in 10.164.0.12 10.164.0.6 10.164.0.11 10.164.0.8 10.164.0.9 10.164.0.10 10.164.0.13 10.164.0.14 10.164.0.15 10.164.0.16; do
  ssh -i ~/.ssh/google_compute_engine -o StrictHostKeyChecking=no henriquecostavale@$h "pkill -f node; pkill -f benchmark_client" 2>/dev/null
done
sleep 5
```

---

## Part C — Resource monitoring (CPU / network) — works for either codebase

`monitor_cluster.py` lives in `~/Sparse_Bullshark`. Run it in one terminal,
start the benchmark in another right after:

```bash
cd ~/Sparse_Bullshark
python3 monitor_cluster.py --hosts-file shared/nodes_distributed.csv --duration 85
```

For a Narwhal run, point it at that topology file instead (adjust the path
for wherever you run it from):

```bash
python3 monitor_cluster.py --hosts-file ../sailfish/benchmark/topology_10.csv --duration 85
```

Prints per-machine CPU% avg/peak, NIC Tx/Rx Mbps, and a resource-bound
verdict — tells you whether a slow result is the protocol or a saturated
machine.

---