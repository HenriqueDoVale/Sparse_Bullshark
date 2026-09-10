#!/usr/bin/env python3
"""
monitor_cluster.py — sample machine-level CPU / NIC / load / memory on every
cluster VM for the duration of a benchmark run, then print a per-machine
summary and a resource-bound verdict.

Harness-agnostic: run it in a second terminal right before you start a run of
`run_distributed.py` OR the Narwhal `run_cluster.py`. The per-process CPU that
our own binary now prints is exact for one node; this fills in the machine view
(all co-located node processes + workers + client + the NIC they share), which
is what tells you whether a throughput drop is contention or protocol.

Usage:
    python3 monitor_cluster.py --hosts-file shared/nodes_distributed.csv --duration 85
    python3 monitor_cluster.py --hosts "10.164.0.6 10.164.0.11" --duration 85 --trim 10

`--hosts-file` accepts one IP per line, or a CSV with an `id,host,...` header
(the Narwhal `topology_10.csv` works directly). Duplicate hosts (co-located
runs) are collapsed to one sampler per machine.
"""

import argparse
import concurrent.futures
import csv
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

SSH_KEY_DEFAULT = os.path.expanduser("~/.ssh/google_compute_engine")
SSH_USER_DEFAULT = os.environ.get("SB_SSH_USER", "henriquecostavale")
SSH_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
            "-o", "LogLevel=ERROR"]

# POSIX-sh sampler. Writes one row per tick to /tmp/sb_sysmon.csv, then exits.
# Prints NPROC / MACHINE / DONE on stdout so the caller learns the core count
# and machine type from the same SSH call.
REMOTE_SAMPLER = r"""
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
echo "NPROC=$(nproc)"
MT=$(curl -s -H 'Metadata-Flavor: Google' \
     http://metadata.google.internal/computeMetadata/v1/instance/machine-type 2>/dev/null \
     | sed 's#.*/##')
echo "MACHINE=${MT:-unknown}"
echo "IFACE=${IFACE:-unknown}"
DUR=%(dur)d
INT=%(int)s
END=$(( $(date +%%s) + DUR ))
echo "ts,busy,idle,load1,memtotal,memavail,rx,tx" > /tmp/sb_sysmon.csv
while [ "$(date +%%s)" -lt "$END" ]; do
  set -- $(head -1 /proc/stat)
  # $1=cpu $2=user $3=nice $4=system $5=idle $6=iowait $7=irq $8=softirq $9=steal
  BUSY=$(( $2 + $3 + $4 + $7 + $8 + $9 ))
  IDLE=$(( $5 + $6 ))
  LOAD=$(cut -d' ' -f1 /proc/loadavg)
  MT2=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
  MA=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  RX=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
  TX=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  echo "$(date +%%s.%%N),$BUSY,$IDLE,$LOAD,$MT2,$MA,$RX,$TX" >> /tmp/sb_sysmon.csv
  sleep $INT
done
echo DONE
"""


def parse_hosts(args):
    if args.hosts:
        raw = args.hosts.replace(",", " ").split()
    else:
        raw = []
        with open(args.hosts_file, newline="") as f:
            first = f.readline().strip()
            is_csv = "," in first and not first.split(",")[0].strip().replace(".", "").isdigit()
            f.seek(0)
            if is_csv:
                for row in csv.DictReader(f):
                    host = (row.get("host") or row.get("ip") or "").strip()
                    if host:
                        raw.append(host)
            else:
                for line in f:
                    line = line.split("#")[0].strip()
                    if not line:
                        continue
                    # tolerate "user@ext,internal" forms — take the last field
                    raw.append(line.replace(",", " ").split()[-1])
    seen, hosts = set(), []
    for h in raw:
        if h not in seen:
            seen.add(h)
            hosts.append(h)
    return hosts


def sample_host(host, key, user, duration, interval, out_dir, host_count):
    script = REMOTE_SAMPLER % {"dur": duration, "int": interval}
    target = f"{user}@{host}"
    meta = {"nproc": None, "machine": "unknown", "iface": "unknown"}
    try:
        proc = subprocess.run(
            ["ssh", "-i", key, *SSH_OPTS, target, "sh", "-s"],
            input=script, capture_output=True, text=True,
            timeout=duration + 45,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("NPROC="):
                meta["nproc"] = int(line[6:] or 0)
            elif line.startswith("MACHINE="):
                meta["machine"] = line[8:]
            elif line.startswith("IFACE="):
                meta["iface"] = line[6:]
        if "DONE" not in proc.stdout:
            return host, meta, None, f"sampler did not finish: {proc.stderr.strip()[:200]}"
    except subprocess.TimeoutExpired:
        return host, meta, None, "ssh timed out"

    local = out_dir / f"{host}.csv"
    try:
        subprocess.run(
            ["scp", "-i", key, *SSH_OPTS, f"{target}:/tmp/sb_sysmon.csv", str(local)],
            capture_output=True, text=True, timeout=60, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return host, meta, None, f"scp failed: {e}"

    rows = []
    with open(local, newline="") as f:
        for r in csv.DictReader(f):
            try:
                rows.append({k: float(v) for k, v in r.items()})
            except ValueError:
                pass
    return host, meta, rows, None


def reduce_rows(rows, trim):
    """Turn raw counter rows into per-interval rates; drop the trim window."""
    if len(rows) < 3:
        return None
    t0, t1 = rows[0]["ts"], rows[-1]["ts"]
    cpu, txm, rxm, load, mem = [], [], [], [], []
    for a, b in zip(rows, rows[1:]):
        dt = b["ts"] - a["ts"]
        if dt <= 0:
            continue
        if b["ts"] - t0 < trim or t1 - b["ts"] < trim:
            continue
        dbusy = b["busy"] - a["busy"]
        didle = b["idle"] - a["idle"]
        if dbusy + didle > 0:
            cpu.append(100.0 * dbusy / (dbusy + didle))
        txm.append((b["tx"] - a["tx"]) * 8.0 / dt / 1e6)
        rxm.append((b["rx"] - a["rx"]) * 8.0 / dt / 1e6)
        load.append(b["load1"])
        if b["memtotal"] > 0:
            mem.append(100.0 * (b["memtotal"] - b["memavail"]) / b["memtotal"])
    if not cpu:
        return None
    return {
        "n": len(cpu),
        "cpu_avg": statistics.mean(cpu), "cpu_peak": max(cpu),
        "tx_avg": statistics.mean(txm), "tx_peak": max(txm),
        "rx_avg": statistics.mean(rxm), "rx_peak": max(rxm),
        "load_end": load[-1] if load else 0.0,
        "mem_peak": max(mem) if mem else 0.0,
    }


def egress_cap_gbps(nproc):
    # GCP rule of thumb: 2 Gbps per vCPU, default cap 32 Gbps (no Tier_1).
    if not nproc:
        return None
    return min(2 * nproc, 32)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--hosts-file")
    g.add_argument("--hosts", help="space/comma separated IPs")
    ap.add_argument("--duration", type=int, required=True,
                    help="seconds to sample — set a bit longer than the run "
                         "(startup + 60s exec); trim absorbs the edges")
    ap.add_argument("--interval", default="1", help="sample period seconds (default 1)")
    ap.add_argument("--trim", type=float, default=5.0,
                    help="seconds dropped from each end before stats (default 5)")
    ap.add_argument("--ssh-key", default=SSH_KEY_DEFAULT)
    ap.add_argument("--user", default=SSH_USER_DEFAULT)
    ap.add_argument("--out", default=None, help="dir for raw per-host CSVs")
    args = ap.parse_args()

    hosts = parse_hosts(args)
    if not hosts:
        print("No hosts parsed.", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out or f"cluster-results/sysmon-{int(time.time())}")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Sampling {len(hosts)} machine(s) for {args.duration}s "
          f"(interval {args.interval}s, trim {args.trim}s/end)")
    print("Start your benchmark run now.\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(hosts)) as ex:
        futs = [ex.submit(sample_host, h, args.ssh_key, args.user,
                          args.duration, args.interval, out_dir, len(hosts))
                for h in hosts]
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda r: hosts.index(r[0]))

    hdr = (f"{'machine':<15} {'type':<16} {'cores':>5} {'CPU% avg/peak':>15} "
           f"{'load1':>6} {'NIC Tx Mbps a/p':>18} {'NIC Rx Mbps a/p':>18} "
           f"{'NIC peak %cap':>13} {'mem%':>6}")
    print(hdr)
    print("-" * len(hdr))

    verdicts = []
    for host, meta, rows, err in results:
        if err:
            print(f"{host:<15} ERROR: {err}")
            continue
        stat = reduce_rows(rows, args.trim)
        if not stat:
            print(f"{host:<15} (not enough samples — run/trim mismatch?)")
            continue
        cap = egress_cap_gbps(meta["nproc"])
        nic_pct = (stat["tx_peak"] / (cap * 1000) * 100) if cap else float("nan")
        print(f"{host:<15} {meta['machine']:<16} {str(meta['nproc'] or '?'):>5} "
              f"{stat['cpu_avg']:>6.0f}/{stat['cpu_peak']:<7.0f} "
              f"{stat['load_end']:>6.1f} "
              f"{stat['tx_avg']:>8.0f}/{stat['tx_peak']:<8.0f} "
              f"{stat['rx_avg']:>8.0f}/{stat['rx_peak']:<8.0f} "
              f"{nic_pct:>12.0f}% {stat['mem_peak']:>5.0f}")

        tags = []
        if stat["cpu_peak"] > 85:
            tags.append("CPU-BOUND")
        elif stat["cpu_peak"] > 65:
            tags.append("cpu-warm")
        if cap and nic_pct > 80:
            tags.append("NIC-BOUND")
        elif cap and nic_pct > 50:
            tags.append("nic-warm")
        if meta["nproc"] and stat["load_end"] > 1.5 * meta["nproc"]:
            tags.append("run-queue-deep")
        verdicts.append((host, tags))

    print()
    hard = [h for h, t in verdicts if "CPU-BOUND" in t or "NIC-BOUND" in t]
    warm = {h: t for h, t in verdicts if t and h not in hard}
    if hard:
        print(f"VERDICT: resource-bound on {', '.join(hard)} — throughput/latency "
              f"at this workload is NOT a clean protocol measurement.")
        if warm:
            print(f"         also warming: {warm}")
    elif warm:
        print(f"VERDICT: headroom left, but warming: {warm}")
    else:
        print("VERDICT: no machine near CPU or NIC limits — "
              "results at this workload reflect the protocol, not the testbed.")
    print(f"\nRaw per-host samples: {out_dir}")


if __name__ == "__main__":
    main()
