# PRBC_C testing — the S1/S2 sample-size constant

Objective 3 of the "4 new objectives" set (see `CLAUDE.md`). Working record of
varying `PRBC_C` (the constant in `sample_size = ceil(C·√n)` that sizes the
S1/S2 relay redundancy set) and measuring both what it costs and what it buys.
Kept as a durable record for building an artifact from later — see
`RECOVERY_TESTING.md` for the sibling investigation this one reuses the model
and harness from.

## What C actually controls

Two separate relay mechanisms share the same sample size, found by reading
`prbc_sailfish.rs` directly (not assumed):

1. **Batch relay** (`accept_batch`) — a node that receives a batch and finds
   itself in that batch's S1 sample re-forwards the **full 256KB payload** to
   its own S2 sample. Since S1 is the same for every observer (deterministic
   from the digest), exactly `sample_size` nodes each independently relay to
   `sample_size` more nodes — `sample_size²` full-payload relay sends per
   batch, on top of the original one-to-all broadcast the generator already
   does unconditionally.
2. **Propose relay** (`handle_prbc_propose`) — same S1→S2 pattern, but relays
   the small vertex (32-byte digest + metadata), not the payload. Same
   quadratic shape, far cheaper per instance.

## Code change

`PRBC_C` (was a hardcoded `const = 1.4`) is now `fn prbc_c()`, read from
`PRBC_SAMPLE_C` at runtime (env var, unset = 1.4, same as before). New
`--sample-c` flag on `run_distributed.py`, PRBC-only. The `+ CONFIG` block now
prints `Sample C` and `Sample size` so every run self-confirms what it
actually used — this mattered a lot (see gotchas below).

## Test design

Fixed: n=10 (1 node/machine, no co-location), 20,000 tx/s, C ∈
{0.5, 0.8, 1.0, 1.4 (default), 1.8, 2.2, 3.0} → sample size ∈
{2, 3, 4, 5, 6, 7, 10 (= n, everyone relays to everyone)}.

- **Sweep A (cost)**: no fault, measures Dissemination network bytes, CPU,
  consensus TPS/latency as C varies.
- **Sweep B (benefit)**: node 0 = Byz1 (as in `RECOVERY_TESTING.md`),
  `--recovery-timeout-ms 50`, measures genuine recovery need on the two
  excluded nodes (8, 9) as C varies, checked against a generalization of the
  validated recovery-probability model to variable sample size.

## Two gotchas hit while running sweep A — both worth knowing for next time

1. **First attempt: `Machines: 2` instead of 10.** All 10 nodes ended up
   running on just two of the ten machines (`10.164.0.12`, `10.164.0.6`),
   confirmed independently by `monitor_cluster.py` showing zero traffic on
   the other eight for the whole window. Root cause not conclusively
   diagnosed (topology file wasn't inspected before re-running) — re-running
   produced a correct `Machines: 10` immediately after, so it was treated as
   resolved rather than root-caused. **If this happens again, check
   `cat shared/nodes_distributed.csv` before re-running** rather than
   assuming a retry fixes it for the same reason.
2. **Second attempt: `Machines: 10` correct, but Dissemination stayed flat
   (~258–260 Mbps) across every C value.** Cause: the cluster binary hadn't
   been rebuilt/redeployed after the `PRBC_C` code change, so
   `PRBC_SAMPLE_C` was silently ignored — confirmed by the `Sample C` /
   `Sample size` lines being completely absent from `+ CONFIG` (not a
   formatting issue — those lines plain didn't exist in the running binary).
   Every one of those 7 runs secretly used the true default (1.4). Fixed with
   `git pull && cargo build --release && bash setup_cluster.sh`, verified via
   a throwaway run showing the new CONFIG lines before redoing the sweep.
   **Silver lining:** those 7 mislabeled runs are still valid as 7 repeated
   samples of the true C=1.4 condition (Dissemination ranged 258.0–260.2 Mbps
   across them — under 1% spread, a useful noise-floor reference).

## Sweep A results — the cost of redundancy

| C | sample size | Dissemination Mbps | Process CPU (machine) | Consensus-data TX (B) | Consensus latency | E2E latency |
|---|---|---|---|---|---|---|
| 0.5 | 2 | 103.3 | 1.3% | 1,670,205 | 475.8 ms | 485.2 ms |
| 0.8 | 3 | 140.3 | 1.6% | 2,193,028 | 476.0 ms | 486.4 ms |
| 1.0 | 4 | 192.1 | 1.9% | 2,899,800 | 476.0 ms | 486.9 ms |
| 1.4 (default) | 5 | 258.4 | 2.4% | 3,818,827 | 476.2 ms | 487.9 ms |
| 1.8 | 6 | 340.1 | 3.0% | 4,970,523 | 476.1 ms | 488.2 ms |
| 2.2 | 7 | 435.6 | 3.7% | 6,295,739 | 476.2 ms | 489.6 ms |
| 3.0 | 10 | 813.1 | 5.9% | 13,067,234 | 477.0 ms | 493.1 ms |

**Fitted model: `Dissemination Mbps = 73.7 + 7.393 × sample_size²`.** Residuals
under 0.4 Mbps at every one of the 7 points spanning 103→813 Mbps — essentially
exact. The `73.7 Mbps` base term independently matches a direct calculation:
each node generates 1/10 of 20,000 tx/s = 2,000 tx/s of its own transactions
at 512B, broadcast once to the other 9 peers = 2,000 × 512 × 9 × 8 bits =
73.728 Mbps. **The base is precisely the one-to-all broadcast; everything
above it is S1→S2 relay redundancy, and that redundancy scales as
sample_size².**

**Redundancy fraction:**
- At the default (sample size 5): 184.8 of 258.5 Mbps is relay redundancy —
  **71.5%** of all Dissemination traffic is redundant, not new information.
- At the maximum (sample size 10): 739.3 of 813.0 Mbps — **90.9%** redundant.

This is the leading candidate answer for objective 2 ("why does PRBC use more
network than Narwhal") — at the *default* setting alone, PRBC sends 3.5× the
bare-minimum-broadcast traffic, entirely from this deliberate redundancy
layer.

**CPU scales far more gently** — power-law fit gives exponent ≈0.94 (close to
linear, not quadratic) — and even at the most extreme setting (sample size
10, 8× the Dissemination load), machine CPU only reached 5.9%, nowhere near a
bottleneck.

**Consensus never moved**: 475.8–477.0 ms consensus latency and 19,842 TPS
identical across the entire sweep, confirming the 3-plane isolation holds
even under an 8× swing in Dissemination-plane load.

## Sweep B results — the benefit of redundancy

Predicted genuine-recovery count (n=10, quorum=7, 239 rounds — same reference
count used throughout `RECOVERY_TESTING.md`) vs. observed `Recovery resp OK`
on nodes 8 and 9 (the two nodes Byz1 excludes):

| C | sample size | Predicted | Observed (node 8) | Observed (node 9) | Observed avg | Ratio |
|---|---|---|---|---|---|---|
| 0.5 | 2 | 176.5 | 183 | 165 | 174.0 | 0.99× |
| 0.8 | 3 | 116.7 | 128 | 111 | 119.5 | 1.02× |
| 1.0 | 4 | 61.6 | 70 | 70 | 70.0 | 1.14× |
| 1.4 (default) | 5 | 24.3 | 22 | 17 | 19.5 | 0.80× |
| 1.8 | 6 | 6.4 | 8 | 9 | 8.5 | 1.33× |
| 2.2 | 7 | 0.9 | 1 | 1 | 1.0 | 1.11× |
| 3.0 | 10 | 0.0 | 1 | 1 | 1.0 | — |

**Match holds within 20% across nearly two orders of magnitude** (176 down to
~1), within 2% at the two highest-signal points (0.5, 0.8). The larger-looking
ratios at 1.8/2.2 are noise on tiny absolute counts (2-event differences), not
a model breakdown. The model correctly predicted **where the cliff is** — need
collapsing to near-zero around sample size 6–7 — and correctly predicted that
**sample size = n (everyone relays to everyone) makes genuine recovery
mathematically unnecessary**; the residual 1-per-node at C=3.0 is
indistinguishable from ordinary background jitter, not evidence against the
claim.

Consensus was flat here too: 475.9–476.4 ms, 19,842 TPS in every run,
`Faults: 1 node(s)` and the `BYZ1: PRBCPropose to only 7/9 peers` log
confirmed on every run.

## The combined tradeoff (the actual "objective 3" answer)

| | vs. default (C=1.4) | Network cost | Recovery need |
|---|---|---|---|
| C=1.8 | +30% network | ~0.35× (a 65% cut) |
| C=3.0 (max) | +215% network (3.1×) | ~0.04× (eliminated, residual = noise) |

Moving from the default to C≈1.8 buys a large reliability improvement for a
modest network cost. Pushing to the maximum triples network cost to eliminate
the last sliver of already-small residual risk — steep diminishing returns
past roughly sample size 6–7 for this n=10 committee.

## Commands used

```bash
# Sweep A (cost, no fault)
for C in 0.5 0.8 1.0 1.4 1.8 2.2 3.0; do
  python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish \
    --n-nodes 10 --input-rate 20000 --sample-c $C
done

# Sweep B (benefit, Byz1 on node 0)
for C in 0.5 0.8 1.0 1.4 1.8 2.2 3.0; do
  sed -i '/^0,/s/,ok$/,byz1/' shared/nodes_distributed.csv
  python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish \
    --n-nodes 10 --input-rate 20000 --sample-c $C --recovery-timeout-ms 50 --logs
  sed -i '/^0,/s/,byz1$/,ok/' shared/nodes_distributed.csv
done
```

Before trusting any run: confirm `Machines: 10`, and for sweep A/B specifically,
confirm `Sample C` / `Sample size` in `+ CONFIG` match what was requested
(this is the exact check that caught the stale-binary gotcha above).

## Pending

- Objective 2 (why Narwhal uses less network than PRBC) — this file's
  redundancy-fraction finding is the leading candidate explanation; needs
  Narwhal-side data + code access to confirm.
- Objective 4 (fixed-latency TPS comparison, PRBC vs Narwhal) — not started.
- Optional polish: repeat sweep B at C=1.8/2.2 a second time to tighten the
  confidence interval on the noisiest (smallest-count) points, same treatment
  given to the n=7–10 sweep in `RECOVERY_TESTING.md`.
