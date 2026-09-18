# CLAUDE.md — Sparse Bullshark / PRBC-Sailfish thesis repo

Working notes for AI assistants. This is a **research benchmarking repo**, not a
product. The goal is a thesis comparison, so correctness of the *measurement* and
honest reporting matter more than polish.

## What this project is

PhD thesis benchmarking **PRBC-Sailfish** (our protocol, digest-only consensus
path) against baseline DAG-BFT protocols — **Sailfish inline** and **Narwhal
Sailfish** — on a GCP cluster. The central claim the professor asked us to
support:

> Fix a system setup, test with workloads 1000/5000/10000/15000/20000 tx/s, and
> show our protocol's latency is better than Narwhal Sailfish.

## Repo layout

Rust workspace (`Cargo.toml` → `shared`, `sparse_bullshark`). One binary,
`target/release/sparse_bullshark`, selects a protocol at runtime via the
`PROTOCOL` env var (`sparse` | `dense` | `sailfish` | `prbc_sailfish`).

| Path | What it is |
|---|---|
| `sparse_bullshark/src/main.rs` | Entry point; `PROTOCOL` env var dispatches to a consensus struct |
| `sparse_bullshark/src/consensus/prbc_sailfish.rs` | **Our protocol** (2307 lines). 3-plane TCP, digest-only consensus |
| `sparse_bullshark/src/consensus/sailfish.rs` | Baseline Sailfish (1096 lines). Inline payload OR `--decoupled` |
| `sparse_bullshark/src/consensus/rbc/` | Pluggable RBC: `bracha.rs`, `signed_vote.rs`, `mod.rs` (trait) |
| `sparse_bullshark/src/consensus/mempool.rs` | `BatchStore` — digest→payload cache for decoupled mode |
| `sparse_bullshark/src/consensus/dag.rs` | `DAG` / `PRBCDag` — vertex store, round index, pruning |
| `sparse_bullshark/src/types/vertex.rs` | `Vertex` (with `weak_edges`), `TimeoutCertificate`, `NoVoteCertificate` |
| `sparse_bullshark/src/network/prbc_message.rs` | PRBC wire messages (Batch / Propose / Vote / Recovery / RecoveryResp / Timeout) |
| `shared/` | Environment loading, key management, transaction generator, VRF |
| `run_linux.py` | **Local** multi-process run; median CONFIG+RESULTS block. Reads `shared/nodes.csv` |
| `run_distributed.py` | **GCP cluster** run of our binary over SSH. Reads `shared/nodes_distributed.csv` |
| `run_cluster.py` | Hasan's 1760-line SSH/GCP deploy+run for our binary (alt to `run_distributed.py`) |
| `bench.py` | Batch driver: edit `EXPERIMENTS`, calls `run_linux.py`, prints comparison table |
| `setup_cluster.sh` | One-time: generate `nodes_distributed.csv`, scp binary+keys+config to every VM |

> **Name collision:** the Narwhal baseline has its *own* `run_cluster.py` at
> `~/sailfish/benchmark/run_cluster.py` on node-0 (nibeshrestha/sailfish repo).
> Unrelated to this repo's `run_cluster.py`. See Testing → Narwhal below.

## Architecture essentials

### PRBC-Sailfish 3-plane TCP (`prbc_sailfish.rs`)

`enum TrafficPlane { Control=0, ConsensusData=1, Dissemination=2 }` — each is a
**separate TCP connection** between every node pair, with its own drain budget
(`CONTROL_DRAIN_BUDGET=256`, `CONSENSUS_DATA_DRAIN_BUDGET=64`,
`DISSEMINATION_DRAIN_BUDGET=16`). `TrafficPlane::for_message` routes:

- **Control**: `PRBCVote`, `PRBCRecovery`, `Timeout` — tiny, latency-critical
- **ConsensusData**: `PRBCPropose`, `PRBCRecoveryResp` — vertex bodies
- **Dissemination**: `Batch` — the 256KB transaction payloads

The consensus path carries only **32-byte SHA-256 batch digests** (`Vertex.block`
is one digest). Vote messages stay tiny regardless of block size — this is why
PRBC holds up under WAN while Sailfish inline collapses.

### Commit path

`PRBCVote` → 2f+1 votes → `hash_committed[(round,source)]` set (this is the
"first message" equivalent, one round trip) → `may_advance_round` (needs 2f+1
hash-committed vertices) → `try_committing_prbc` (leader witnessed by 2f+1 in
r+1) → `commit_causal_history_prbc` (traverses **strong + weak** edges) →
`on_execution_ready` once the payload is verified.

**Payload lag ≠ error.** A digest-vote quorum (Control plane, tiny) routinely
completes before the 256KB payload finishes on the Dissemination plane. That arms
`start_recovery`, but `tick_recovery` only sends a `PRBCRecovery` after
`RECOVERY_TIMEOUT_MS` (500ms) and `on_execution_ready` cancels it the instant the
propose/batch lands — the common case. Stats counters:
`Payload-lag events` (quorum before local payload) ≈ `Payload post-quorum`
(propose then arrived on its own), while `Network recoveries` / `Recovery resp OK`
(actual wire fetches) stay near zero. High lag count with ~zero network
recoveries = the plane decoupling working, not a failure.

### Decoupled mempool (`sailfish.rs` + `mempool.rs`)

`MEMPOOL_MODE=decoupled` makes Sailfish carry digests instead of inline payload
(Narwhal-style), so the same binary benchmarks both. Without it, `Vertex.block`
holds the full payload and is re-forwarded on every echo/vote/ready — O(n²)
payload traffic, which is the inline collapse.

### RBC plugin layer

`Box<dyn ReliableBroadcast>` chosen at construction by `RBC_MODE`
(`signed_vote` | default `bracha`). `on_val/on_echo/on_ready/on_vote/on_commit`
each return `Some(vertex)` exactly on RBC-delivery. Sailfish `--rbc signed_vote`
is the "inline signed vote" variant used in the WAN experiment.

## Runtime env vars (all optional unless noted)

| Var | Effect |
|---|---|
| `PROTOCOL` | **required** on cluster: `sailfish` / `prbc_sailfish` / `sparse` / `dense` |
| `INPUT_RATE` | aggregate tx/s cap (0 = unlimited) |
| `RBC_MODE` | `signed_vote` or `bracha` (sailfish only) |
| `MEMPOOL_MODE` | `decoupled` → digest-carrying vertices |
| `PRBC_SIGS` | `off` disables Ed25519 vote sigs (prbc only; default on) |
| `REDUCED_QUORUM` | `on` → f+1 instead of 2f+1 (**CFT, not BFT-safe** — experiments only) |
| `ROUND_TIMEOUT_MS` | round timeout, default 500 |
| `RECOVERY_TIMEOUT_MS` | Phase-3 recovery retry timeout |
| `NETWORK_MBPS` / `CONSENSUS_NETWORK_PERCENT` | dissemination-plane bandwidth pacer |
| `PRBC_SAMPLE_C` | PRBC only — overrides the `1.4` in `sample_size=ceil(C·√n)` for the S1/S2 relay set. Bigger = more redundancy/network, fewer genuine recoveries |

`EXECUTION_DURATION = 60` (seconds) is a compile-time const in both consensus files.

## Testing / benchmarking

### Local (one machine, N processes)

```bash
cargo build --release
python3 run_linux.py --tx-size 512 --n-tx 500 --mode prbc_sailfish --input-rate 20000
python3 run_linux.py --tx-size 512 --n-tx 500 --mode sailfish --rbc signed_vote
```

`run_linux.py` regenerates nothing — it reads `shared/nodes.csv` as-is. `bench.py`
regenerates `shared/nodes.csv` for each entry in its `EXPERIMENTS` list.
Output: one `+ CONFIG` / `+ RESULTS` block, **median across nodes**. Key metrics:
`Consensus TPS`, `Consensus latency` (vertex-creation→commit), `E2E latency`
(batch-ready→commit, own vertices only), `Batches cached` (health: >200 borderline,
>5000 discard the run).

### GCP cluster — our binary

10 VMs, internal IPs in `setup_cluster.sh` (`10.164.0.12` is node-0 / the
orchestrator; the other 9 are `.6 .11 .8 .9 .10 .13 .14 .15 .16`). One-time:
`bash setup_cluster.sh`. Then from `~/Sparse_Bullshark` on node-0:

```bash
python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish --n-nodes 10 --input-rate 20000
python3 run_distributed.py --tx-size 512 --n-tx 500 --mode sailfish --rbc signed_vote --n-nodes 10 --input-rate 10000
```

`--n-nodes N` truncates the topology to the first N rows. `--decoupled`,
`--wan-delay MS`, `--reduced-quorum`, `--no-prbc-sigs` are the other flags.
`run_distributed.py` builds a bash script per machine, SSHes in, runs all assigned
nodes, greps the per-node output between `__SB_NODE_i_START__/END__` markers,
prints the median. 180s SSH timeout.

**Current cluster state:** 1 node per machine (setup_cluster.sh was regenerated
after a reset — it used to be 5 nodes/machine). Clean 1:1 machine mapping, good
for WAN work.

### GCP cluster — Narwhal Sailfish baseline

Separate repo at `~/sailfish` on node-0 (nibeshrestha/sailfish). Run from
`~/sailfish/benchmark`:

```bash
python3 run_cluster.py --topology topology_10.csv --workers 1 --tx-size 512 \
  --faults 0 --duration 60 --batch-size 512000 --max-batch-delay 50 --target-rate 20000
```

`topology_10.csv` = `id,host` with the same 10 GCP IPs. Output: `Consensus
latency` and `End-to-end latency` (ms). Its `scp_glob_from` default `timeout=60`
is too short under WAN delay — bump to 300 (`sed` on line ~278).

**This harness does NOT reliably kill nodes between runs.** Always `pkill -f node;
pkill -f benchmark_client` across all 10 hosts before each run, or results from a
stale overlapping run are silently fast/wrong (seen: 15k "258 ms" anomaly).

### Resource measurement (CPU + network per run)

**Per-process, in our binary** (`utils/metrics.rs`): both `prbc_sailfish.rs` and
`sailfish.rs` start a `ResourceMeter` when the 60s window begins and print, in
`+ RESULTS`: `Process CPU 1core %`, `Process CPU machine %`, `user/sys CPU s`,
`peak RSS MB`, `Machine cores`. Sailfish also gets `Network TX/RX MB` and
`TX/RX Mbps` from `WireCounters` (byte tallies at the dispatcher send and the
per-connection read; PRBC already had its per-plane breakdown). Linux-only —
falls back to `Process CPU: n/a` off `/proc`. `run_distributed.py` /
`run_linux.py` median these lines automatically (no parser change).

**Machine-level, any run** (`monitor_cluster.py`, repo root): SSH-samples every
VM's `/proc/stat`, `/proc/net/dev`, loadavg, meminfo at 1 Hz for a chosen
window, then prints per-machine CPU% avg/peak, NIC Tx/Rx Mbps avg/peak, NIC peak
as % of the GCP egress cap (~2 Gbps/vCPU), load1, mem%, and a
resource-bound verdict. This is the only resource view available for the Narwhal
baseline, and the one that captures co-located contention (5 node processes +
workers sharing one machine). Run it in a second terminal:

```bash
python3 monitor_cluster.py --hosts-file shared/nodes_distributed.csv --duration 85
# then immediately start the benchmark; --trim 5 drops the ramp/teardown edges
```

Use both together to answer "is this data point protocol behaviour or a
saturated testbed?" — e.g. the Narwhal 30→50 node throughput drop
(123,200 → 44,035 TPS): if `monitor_cluster.py` shows CPU peak ~100% / deep run
queue on the 50-node run, it's contention, not a Sailfish scaling limit.

### WAN emulation (`tc netem`)

One-way delay on each VM's default interface; RTT ≈ 2× value.

```bash
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
sudo tc qdisc add dev "$IFACE" root netem delay 25ms   # 50ms RTT
sudo tc qdisc del dev "$IFACE" root                     # clear
```

- `run_distributed.py --wan-delay MS` does this automatically (setup + teardown
  inside the per-machine script). This path is proven.
- For Narwhal, `tc` must be applied out-of-band via SSH. **Do NOT apply it to
  node-0** — node-0's own SSH/scp control traffic gets delayed and config
  distribution / log collection time out. Apply only to the other 9, in
  **parallel** (`&` + `wait`), each SSH wrapped in `timeout 30` with
  `-o ConnectTimeout=15 -o ServerAliveInterval=5`.
- **Failure mode:** stacked/failed `tc` attempts + Ctrl-C left all 9 VMs
  unreachable twice this project. Recovery = reset VMs from GCP Console, then
  re-run `setup_cluster.sh`. Clear node-0's `tc` **locally** first (not via SSH)
  when SSH is hanging.

## Benchmark results so far (n=10, 1 node/machine, 512B tx, LAN unless noted)

**Workload sweep — E2E latency (ms):**

| tx/s | PRBC-Sailfish | Narwhal Sailfish | Sailfish inline |
|---|---|---|---|
| 1,000 | 9,456 | 2,966 | (in artifact) |
| 5,000 | 1,900 | 2,385 | |
| 10,000 | 950 | 1,696 | |
| 15,000 | 634 | 652 | |
| 20,000 | 475 | 1,228 | |

PRBC wins 5k–20k (2.6× at 20k). **Narwhal wins at 1k** — PRBC waits for
`--n-tx 500` per batch; at 100 tx/s/node that's a 5s fill. Narwhal's
`max-batch-delay=50ms` ships partial batches. Report this honestly.

**WAN (PRBC vs Sailfish inline):** PRBC stable at 0/50/100ms RTT (19,842 TPS /
487ms at 20k @ 100ms RTT). Sailfish inline collapses >5k tx/s at 100ms RTT
(3,025 TPS at 20k input). Digest-only consensus path is the reason.

**Sailfish inline scaling:** rounds/s 18.6 (n=10) → 2.1 (n=20) → 0.9 (n=30) →
deadlock (n=50). O(n²) inline-payload amplification.

### Pending

- **Narwhal WAN sweep** (25ms + 50ms one-way × 5 rates) — attempted, blocked by
  the `tc`-breaks-SSH issue; VMs were reset. Use the exclude-node-0 + parallel-SSH
  + `scp timeout=300` recipe above. (Note: Narwhal is also digest-based, so it is
  expected to be WAN-resistant like PRBC — this sweep mostly confirms, it is not
  the headline result.)
- Update the WAN artifact with Narwhal once collected.
- Artifacts (claude.ai): `benchmark_summary` `53d58a79-...`, `wan_experiment`
  `7067df05-...`.
- **Recovery-mechanism testing** (Byz1 fault injection, timeout sweeps,
  theoretical model vs. observed escalation rate across n=7-10) — full
  writeup in `RECOVERY_TESTING.md`. f=3 simultaneous-fault test in progress.

## Professor's correctness points (all addressed — see memory `protocol_feedback.md`)

Leader payload guard in `try_committing_prbc`; `weak_edges` on `Vertex` traversed
in `commit_causal_history*`; Ed25519 vote sigs (`PRBC_SIGS`); timeout certificate
round-advance; Sailfish commit on ≥2f+1 **first messages** not full RBC delivery
(`first_messages` map / `record_first_message`).

Remote branches: `origin/prbc-performance-improvements` (Hasan's, `b9735e1` — the
big PRBC + `run_cluster.py` commit), `origin/optimization`,
`origin/rbc-modularization`.

## Gotchas

- Windows dev box, cluster is Linux GCP. `run_linux.py` handles the `.exe` suffix.
- `shared/nodes.csv` (local, 7 nodes) vs `shared/nodes_distributed.csv` (cluster,
  generated by `setup_cluster.sh`, not in git).
- At 1k–20k tx/s every protocol here is **timeout-dominated**, not
  bandwidth-bound — WAN delay barely moves *consensus* latency; it shows up in
  *E2E*. Ceilings (where output<input): PRBC ~136k LAN, drops with RTT for inline.
- Reruns overlapping a not-killed previous run give garbage. Kill first, `sleep 5`.
