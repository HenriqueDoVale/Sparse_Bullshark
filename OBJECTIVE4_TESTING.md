# Objective 4 testing — fixed-latency-budget throughput comparison

Objective 4 of the "4 new objectives" set (see `CLAUDE.md`). The professor's
meeting suggestion was to fix a latency value (~1000ms) and see where each
protocol lands, rather than only comparing at fixed workloads. This is that
test. Sibling docs: `RECOVERY_TESTING.md`, `PRBC_C_TESTING.md`.

## What "best TPS at ≤1000ms E2E" means

First framing was wrong and is worth recording so it isn't repeated: this is
**not** "find the rate where E2E equals exactly 1000ms." It's "find the
**maximum** throughput a protocol sustains while keeping E2E **at or under**
1000ms" — a throughput-under-SLA question. For a protocol whose latency keeps
*improving* as load increases (PRBC, in its sustainable range), that maximum is
close to its own ceiling, not some low-rate crossing point. The low-rate
crossing is a red herring: it's the *minimum* rate satisfying the budget, not
the *best* one.

## PRBC-Sailfish — E2E latency across the full range

| tx/s | E2E latency | ≤1000ms? |
|---|---|---|
| 1,000 | 9,456 ms | ❌ |
| 5,000 | 1,900 ms | ❌ |
| 8,000 | 1,198.7 ms | ❌ |
| 9,600 | 1,000.2 ms | borderline |
| 10,000 | 950 ms | ✅ |
| 15,000 | 634 ms | ✅ |
| 20,000 | 475 ms | ✅ |
| 80,000 | 137.8 ms | ✅ |
| 110,000 | 108.0 ms | ✅ |
| 130,000 | 98.3 ms | ✅ |
| 140,000 | 147.9 ms | ✅ (past ceiling, rising) |
| 150,000 | 280.8 ms | ✅ (~13k tx/s oversaturated) |

Monotonically decreasing from 1k up to ~130k, then rising again only once
genuinely oversaturated past the ~136-138k ceiling (see `CLAUDE.md` gotchas) —
and even 13k tx/s past that ceiling it's still only 280.8ms, nowhere near the
budget again. **PRBC's E2E crosses 1000ms exactly once in the tested range, on
the low side (~9,600 tx/s, batch-fill-timeout-governed, not a capacity
limit).** It never crosses back on the high side within anything tested.

**Conclusion: PRBC's max TPS at ≤1000ms E2E ≈ its own ceiling, ~136,000-138,000
tx/s.** The 9,600 figure is not the answer to this question — it's the answer
to a different, less useful question ("minimum rate that satisfies the
budget"), and using it would have wrongly made PRBC look 14× worse than it is.

## Narwhal Sailfish — E2E latency across the full range

| tx/s | E2E latency (samples) | Median (n=3) | ≤1000ms? |
|---|---|---|---|
| 1,000 | 2,966 ms | — | ❌ |
| 5,000 | 2,385 ms | — | ❌ |
| 10,000 | 1,696 ms | — | ❌ |
| 15,000 | 652 ms | — | ✅ |
| 16,000 | 1,250 / 1,837 / 1,703 ms | 1,703 ms | ❌ (all 3) |
| 17,000 | 433 ms | — | ✅ |
| 18,000 | 641 ms | — | ✅ |
| 19,000 | 635 / 747 / 1,020 ms | 747 ms | ✅ (2/3) |
| 20,000 | 1,228 / 453 / 1,275 ms | 1,228 ms | ❌ (2/3) |
| 30,000 | 473 ms | — | ✅ |
| 50,000 | 4,200 ms | — | ❌ |
| 100,000 | 3,642 ms | — | ❌ (see caveat) |

**Not monotonic, and not just noisy around a single boundary — genuinely
erratic.** 16k reproducibly violates (all 3 repeats, 1250-1837ms) while its
immediate neighbors 15k and 17k are both comfortably compliant. 20k is
unstable run-to-run (2.7× spread: 453ms to 1,275ms across 3 trials on the
identical target rate). 30k is compliant and *better* than 19k's own median,
despite sitting between two violating points (20k, 50k). Individual
`Consensus non leader latency` values swing widely between runs at the same
rate (165→216→187→199→463→421→208ms), consistent with an intermittently
lagging node (possibly interacting with `Sync retry delay: 10,000ms`) rather
than a smooth function of load.

**Caveat on the 100k point:** the load generator logged `Clients missed their
target rate 100 time(s)` and the run completed in 55s instead of the intended
62s — it could not actually sustain 100k tx/s input, so this point describes
an already-overloaded generator, not a clean measurement of Narwhal at 100k
input. It still clearly violates the budget, so it doesn't change the
conclusion, but it isn't a trustworthy *precise* number.

**Conclusion: Narwhal has no single well-defined "max TPS at ≤1000ms."** Two
honest readings:
- **Best single sample found:** 30,000 tx/s (473ms) — but it's a lone
  compliant point flanked by violations on both sides, not validated by
  repeats the way PRBC's ceiling behavior is.
- **Reliably compliant reading:** ~19,000 tx/s — the region immediately
  around it (16k, 20k) already violates, so this is the more defensible
  "sustained" number if a single figure is required.

## The comparison

| | Max TPS at ≤1000ms E2E | Basis |
|---|---|---|
| **PRBC-Sailfish** | ~136,000-138,000 tx/s | Own ceiling; smooth, monotonic, reproducible across the whole range |
| **Narwhal Sailfish** | ~19,000-30,000 tx/s | Erratic; isolated compliant points, real run-to-run variance up to 2.7× |

**PRBC wins by 4.6-7×**, depending on which end of Narwhal's range is used.
Either reading gives the same qualitative conclusion, and it reinforces rather
than contradicts the original fixed-workload sweep — it does **not** depend on
the discredited "9,600 vs 199k" framing that started this investigation.

A second, independent finding worth keeping: **PRBC's latency-vs-load curve is
smooth and highly reproducible; Narwhal's is not**, at least in the 15k-100k
band on this testbed. That instability is itself evidence for PRBC, separate
from the raw throughput numbers, and is a natural link to objective 1 (why
Narwhal's latency behaves differently from PRBC's) — worth investigating
*why* Narwhal is erratic here, not just *that* it is.

## Gotcha hit during Narwhal testing

One `run_cluster.py` run crashed with a `KeyError` inside Narwhal's own log
parser (`benchmark/logs.py:177`, `_consensus_latency`) — a commit referenced a
proposal digest missing from `self.proposals`, most likely because GC
(`GC depth: 50 round(s)`) pruned it before the log scrape captured it. This is
a bug in the Narwhal benchmark harness, not in our test setup or in the system
under test. A clean solo re-run of the same rate succeeded normally.

## Commands used

PRBC (from `~/Sparse_Bullshark` on node-0):

```bash
python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish \
  --n-nodes 10 --input-rate $RATE
# RATE ∈ {8000, 9600, 10000, 15000, 20000, 80000, 110000, 130000, 140000, 150000}
```

Narwhal (from `~/sailfish/benchmark` on node-0; always kill stale processes
across all 10 hosts first — this harness does not reliably clean up between
runs):

```bash
for h in 10.164.0.12 10.164.0.6 10.164.0.11 10.164.0.8 10.164.0.9 10.164.0.10 \
         10.164.0.13 10.164.0.14 10.164.0.15 10.164.0.16; do
  ssh -i ~/.ssh/google_compute_engine -o StrictHostKeyChecking=no $h \
    "pkill -f node; pkill -f benchmark_client" 2>/dev/null
done
sleep 5
python3 run_cluster.py --topology topology_10.csv --workers 1 --tx-size 512 \
  --faults 0 --duration 60 --batch-size 512000 --max-batch-delay 50 --target-rate $RATE
# RATE ∈ {15000, 16000, 17000, 18000, 19000, 20000, 30000, 50000, 100000}
# 16000, 19000, 20000 repeated 3× each after the erratic pattern emerged
```

## Pending

- Objective 1 (why Narwhal's latency is bigger/less stable than PRBC's) — this
  file's non-monotonicity finding is a concrete starting point; still needs
  Narwhal code access to explain the mechanism, not just observe the effect.
- Objective 2 (why Narwhal uses less network than PRBC) — unchanged from
  `PRBC_C_TESTING.md`: the S1/S2 relay redundancy fraction (71.5-90.9% of
  Dissemination traffic) remains the leading candidate explanation.
- Optional, not required for the conclusion: 2-3 repeats at 30,000 tx/s to
  check whether that point is reproducible or itself a lucky sample, matching
  the treatment already given to 16k/19k/20k. Would sharpen Narwhal's number
  but is very unlikely to change which protocol wins or by roughly how much.
