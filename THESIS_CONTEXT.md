# Thesis writing context — PRBC-Sailfish

This file is for a **separate writing-assistant session** (a plain chat session,
not code-aware, no repo/cluster access — deliberately lightweight). It is not
for related-work or citation research. The job of that session is: the user
provides raw content/notes on a given chapter or section, and the assistant
helps turn that into polished LaTeX prose that fits the thesis's **existing
structure** (table of contents already exists — see below — don't propose a
new outline, slot into the one that exists). Pull exact figures and numbers
from the sibling MD files referenced below rather than inventing or
approximating them.

Upload this file plus the four sibling MD files
(`RECOVERY_TESTING.md`, `PRBC_C_TESTING.md`, `OBJECTIVE1_2_ANALYSIS.md`,
`OBJECTIVE4_TESTING.md`) as context at the start of that session. This file is
deliberately separate from `CLAUDE.md`, which is operational (commands, IPs,
code layout) for the coding/benchmarking session, not useful for prose.

## What this session (Claude Code, the coding/benchmarking agent) actually knows

**Important scope boundary, stated plainly so the writing session doesn't
overreach:** this repo and this session's work cover the **implementation and
evaluation** of an already-designed PRBC-Sailfish system — running it,
measuring it, reading its Rust/Python source, comparing it to Narwhal Sailfish.
This session has **no knowledge of and no input on**:
- the theoretical design of PRBC itself (the VRF-based sampling scheme, the
  probabilistic-safety argument, correctness proofs) — chapters 4–5 territory,
- the related-work survey (chapter 3) — beyond what's summarized below from
  the preliminary report,
- the background chapter (chapter 2) — standard SMR/consensus/DAG definitions.

Those chapters need to come from the user's own design notes, the preliminary
report below, and existing thesis literature — not from this file. What this
file **is** reliable for: chapter 6 (Implementation) and chapter 7
(Evaluation), which is what this session's entire body of work maps onto.

## The thesis, properly scoped

**The contribution:** PRBC-Sailfish — a DAG-based BFT SMR protocol that
replaces the deterministic Reliable Broadcast used by Sailfish's ordering
kernel with a **Probabilistic Reliable Broadcast (PRBC)**. PRBC uses verifiable
random sampling (VRF-based) to disseminate each vertex to a committee of
O(√n) replicas per round instead of all n, cutting broadcast communication
complexity from O(n²) to O(n√n), with a recovery mechanism covering the rare
case where a replica misses the original proposal. Implemented in Rust,
evaluated on a 10-machine GCP cluster for n = 10, 20, 30, 50, against Narwhal
Sailfish (decoupled data dissemination / consensus ordering).

**The honest headline finding, from the thesis's own abstract — this is the
real central claim, not the "PRBC wins" framing from this week's narrower
work:**

> Narwhal Sailfish achieves higher throughput at scale, since its ordering
> layer operates on lightweight digests and proceeds in parallel with
> dissemination. PRBC-Sailfish achieves significantly lower finalization
> latency for small-to-medium systems (10–30 replicas), since it avoids the
> batch-collection windows and multi-round dissemination inherent to the
> decoupled architecture. **This latency advantage narrows as the system
> scales**, since the quadratic-ish per-round message growth still present in
> probabilistic dissemination eventually dominates ordering time at larger
> replica counts.

This is a **scale-dependent trade-off**, not a flat "PRBC is better" claim.
Anything drafted for chapter 7 needs to carry this nuance rather than
overclaiming from the n=10-only work done this week (see below).

## Two separate bodies of evaluation data — don't conflate them

**1. The n=10/20/30/50 scaling comparison** (Narwhal ≈199,680 tx/s ceiling /
868ms latency at n=10, down to PRBC leading both throughput and latency at
n=50) — this is the result the thesis abstract is actually built around. As of
this writing: **only the general shape is known; the user is still re-running
and re-verifying these numbers, so treat none of them as final.** Do not
present specific figures from this dataset in written prose yet — ask the user
for the current, confirmed numbers when drafting this section. The
relationship between this dataset and the n=10-only work below (whether the
latter becomes a supporting deep-dive on the n=10 row, or stays a separate
thread) is **not yet decided** — don't assume a structure, ask.

**2. This week's four objectives, all measured at a fixed n=10** — this
dataset **has** been through rigorous verification (matched settings, repeat
sampling to characterize noise, live measurement cross-checked against
theory) and can be treated as solid, citable content for whichever part of
chapter 7 it ends up supporting:

- **Objectives 1 & 2 — mechanism, not just measurement.** Read Narwhal's
  actual source directly (it's public: `github.com/nibeshrestha/sailfish`).
  Finding: both protocols solve the same problem (a node may need to act
  before it has a payload) with opposite strategies. Narwhal *blocks* twice
  (code-confirmed: a worker waits for 2f delivery acks before a digest is
  header-eligible; a primary suspends header processing until the payload is
  locally present) — this costs latency. PRBC *never blocks* — it votes on
  the digest immediately — this costs network, via a deliberate S1→S2
  redundant relay layer. At n=10, matched throughput (20k tx/s): PRBC uses
  **~3.7–3.8× more network**, confirmed four independent ways (direct code
  reading, a from-scratch combinatorial count off the actual tested settings,
  a fitted empirical model, a live NIC measurement). Full detail:
  `OBJECTIVE1_2_ANALYSIS.md`.
- **Objective 3 — tuning the redundancy dial.** `PRBC_SAMPLE_C` sizes the
  S1→S2 relay committee. Swept across 7 values at n=10: network cost fits
  `73.7 + 7.393×sample_size²` Mbps almost exactly; recovery need collapses
  following a validated hypergeometric model. **C≈1.8 is the sweet spot** — a
  65% cut in recovery need for +30% network. Full detail: `PRBC_C_TESTING.md`.
- **Objective 4 — a fair comparison at a fixed latency budget, at n=10.**
  PRBC's real answer is close to its own ceiling (~136–138k tx/s, since its
  E2E latency is smooth and monotonic and stays under a 1000ms budget almost
  everywhere in its tested range). Narwhal's latency in this range is
  **erratic, not smooth** — real run-to-run variance up to 2.7× at the
  identical target rate. At n=10, PRBC wins this specific comparison
  **4.6–7×**. This is a fixed-n=10 result and should be framed as such — it
  is not evidence about how the trade-off behaves at n=20/30/50, which is a
  separate, not-yet-finalized question. Full detail: `OBJECTIVE4_TESTING.md`.
- **The recovery mechanism, validated against theory** (from earlier work,
  not this week, but part of the same evaluation effort): a first-principles
  hypergeometric probability model for when PRBC's recovery mechanism fires,
  confirmed within 2% at high-confidence points, including correctly
  *predicting* a non-monotonic "bump" in recovery need at n=8 before it was
  measured. This is a genuinely strong methodological result — a model
  validated predictively, not just fitted after the fact — worth real
  emphasis in chapter 7, and arguably relevant to chapter 5's correctness
  discussion too (it's evidence the recovery mechanism behaves as the
  protocol's design predicts). Full detail: `RECOVERY_TESTING.md`.

**A methodology note worth its own paragraph somewhere in chapter 7:** while
investigating objective 2's network gap, a batch-size mismatch was found in
the tested settings (PRBC's batches were 500 tx, Narwhal's were 1,000) and
corrected. Correcting it did **not** weaken PRBC's case — if anything
Narwhal's numbers improved slightly once matched, meaning the original
mismatch was mildly conservative *in Narwhal's favor*. Worth a sentence in a
threats-to-validity discussion: "we checked, it doesn't change the
conclusion, if anything it strengthens it."

**A separate, unimplemented idea — future work, not a result.** A design
discussion (not built, not measured) on an economic mechanism to punish a
Byzantine leader that triggers excessive recoveries: reward for committed
blocks, a fee on the proposer per recovery its block causes, escalating
percentage-based penalties for sustained misbehavior, and a symmetric
statistical check to stop Byzantine requesters from framing an honest
proposer. Candidate material for chapter 8 (future work) — do not present as
an experimental result anywhere.

## Background context from the preliminary report ("Estudo Orientado")

This earlier report is likely the direct source for chapters 2–3 and part of
6, and explains *why* PRBC-Sailfish looks the way it does. Summary:

- **Protocol survey (chapter 3 material):** covers Bullshark, Sparse
  Bullshark, Shoal/Shoal++, Sailfish, Cordial Miners, Mysticeti, Mahi-Mahi as
  DAG-based protocols, plus ProBFT, Simplex, and Probabilistic Simplex as the
  probabilistic/chained baselines PRBC's design borrows ideas from. Table 1 in
  that report gives a comparison of sync model, DAG type (certified/
  uncertified), communication complexity, and latency for each. Note: the new
  ToC lists a "Tribe's" protocol in related work (section 3.8) that does **not**
  appear in this preliminary report — that's new material the writing session
  doesn't have source content for yet.
- **The motivating experiment:** an earlier implementation (Rust) of
  monolithic — i.e., full-payload-in-vertex — Bullshark, Sparse Bullshark, and
  Sailfish, benchmarked against a chained protocol (Practical Simplex) on a
  *physical* 10-machine Dell PowerEdge R410 cluster (different hardware from
  this session's GCP cluster), for n = 4, 7, 10, 34, 67, 100 (n>10 simulated
  via multiple processes per machine). Findings: **Sailfish beat Bullshark and
  Sparse Bullshark** on both throughput (~152k tx/s peak) and latency at small
  n via its 1-round commit rule; Sparse Bullshark was *slightly worse* than
  dense Bullshark at small n, because in a monolithic architecture the
  bottleneck is the O(n) payload traffic, not the O(1) metadata Sparse
  Bullshark optimizes; and critically, **all monolithic DAG protocols hit a
  "bandwidth wall" at n≥34** (collapsing, then ceasing to function by n=67–100)
  while chained Simplex — lower bandwidth footprint per step — stayed stable.
- **Why this motivated the current design:** the bandwidth-wall finding is the
  explicit justification for (a) decoupling data dissemination from consensus
  ordering (Narwhal-style, digest-only ordering) and (b) probabilistic
  dissemination (PRBC) as an alternative/complementary fix to the *quadratic
  broadcast cost itself*, not just the payload-coupling problem.
- **Why Sailfish specifically was chosen as the ordering substrate** (three
  reasons given directly in that report, useful almost verbatim for a
  "protocol selection" chapter): (1) highest observed throughput of the
  candidates, (2) lower finality latency via its 1-round commit rule vs.
  Bullshark's 2-round rule, (3) — the most load-bearing reason — Sailfish's
  "leader-in-every-round" synchronization gives the coordinated stability
  needed once probabilistic dissemination introduces variance into message
  delivery; a protocol that "races ahead" asynchronously (like Bullshark) was
  judged to risk destabilizing ordering under that added stochasticity.

## Chapter map (from the existing table of contents)

1. Introduction — motivation, problem statement, contributions, organization.
2. Background — SMR, consensus, DAGs, blockchain, broadcast primitives,
   complexity metrics, responsiveness/finalization/block time. (Preliminary
   report §2 is close to a direct source for most of this.)
3. Related Work — leader-based (ProBFT, Simplex, ProSimplex), Bullshark family
   (Bullshark, Sparse Bullshark, Shoal/Shoal++, Sailfish), uncertified-DAG
   family (Cordial Miners, Mysticeti, Mahi-Mahi), Tribe's (source unknown to
   this session), final observations/limitations. (Preliminary report §3 is a
   close source for everything except Tribe's.)
4. Designing a new probabilistic broadcast — initial ideas, problems with
   them, final PRBC design, optimizations, system model, protocol spec,
   complexity, correctness proof outline (safety/liveness), comparison with
   Tribes. **Not covered by this session at all** — needs the user's own
   design notes as content.
5. ProSailfish — PRBC + Sailfish combined: system model, differences from
   plain Sailfish, protocol spec, complexity, correctness outline. **Not
   covered by this session** beyond what's visible in the *implementation*
   (see `CLAUDE.md`'s "Commit path" and "Architecture essentials" sections,
   which describe the *as-built* behavior, not the formal spec).
6. Implementation — architecture overview, data structures, challenges,
   "Narwhal vs. our implementation." **High overlap with this session** — see
   `CLAUDE.md`'s repo layout and architecture-essentials sections (3-plane TCP
   design, `TrafficPlane` enum, RBC plugin layer, decoupled mempool) for
   as-built architecture detail.
7. Evaluation — experimental setup, performance analysis. **This is where
   nearly everything in this file's "two bodies of evaluation data" section
   goes.**
8. Conclusion — future work is a natural home for the incentive-mechanism
   proposal described above.

## Where the actual numbers, figures, and code excerpts live

- `RECOVERY_TESTING.md`, `PRBC_C_TESTING.md`, `OBJECTIVE1_2_ANALYSIS.md`,
  `OBJECTIVE4_TESTING.md` — full data and derivations for the n=10 evaluation
  work described above.
- `CLAUDE.md` — main workload-sweep table, WAN results, Sailfish-inline
  scaling numbers, and all implementation/architecture detail. Not needed for
  prose directly, but the source of truth if a number needs double-checking.
- Two claude.ai artifacts with polished charts: **"Past Week's Work"**
  (recovery investigation) and **"This Week's Work"** (objectives 1–4 plus the
  incentive-mechanism discussion) — good for pulling figures from.

## Open items — still needed from the user

1. How the n=10/20/30/50 scaling dataset relates to the n=10-only four
   objectives, structurally in chapter 7 — genuinely undecided, revisit once
   the scaling numbers are finalized.
2. Confirmed, final n=20/30/50 numbers once re-testing is complete — nothing
   from that dataset should be written into the thesis before then.
3. Content for chapters 2–5 (background, related work beyond the preliminary
   report, PRBC's formal design and correctness proofs, ProSailfish spec) —
   entirely outside this session's knowledge; needs the user's own notes.
4. What "Tribe's" (ToC §3.8) refers to — not in the preliminary report shown
   so far.

## How the writing session should work

- **Format:** LaTeX. Table of contents already exists (above) — treat it as
  fixed, don't propose reorganizing it.
- **Workflow:** the user provides raw content/notes for whichever section
  they're drafting; the job is to help turn that into written LaTeX prose, not
  to originate claims or restructure the thesis.
- **No related-work or citation help** — out of scope for that session.
- **No code or cluster access, by design.** If a number is needed that isn't
  in the files listed above, ask rather than estimate.
- **Do not overclaim from the n=10-only work** — always default to the
  scale-dependent framing in the abstract unless the user is specifically
  drafting a subsection scoped to n=10.
