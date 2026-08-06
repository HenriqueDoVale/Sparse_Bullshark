#!/usr/bin/env python3
"""Build, deploy, run, and summarize Sparse Bullshark on SSH or GCP.

The host inventory contains one physical machine per line. A line can be:

    10.0.0.10
    ubuntu@203.0.113.10,10.0.0.10

The optional second form separates the SSH target from the private address
advertised to protocol peers. Processes are assigned to machines round-robin;
additional processes on a machine use consecutive ports beginning at
``--base-port``.

Examples (run from the project root under Linux/WSL):

    python3 run_cluster.py --hosts-file cluster_hosts.txt \
        --nodes 8 --tx-size 512 --n-tx 500 \
        --mode prbc_sailfish --input-rate 50000

    python3 run_cluster.py --hosts-file cluster_hosts.txt \
        --nodes 8 --tx-size 512 --n-tx 500 --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_BINARY = PROJECT_DIR / "target" / "release" / "sparse_bullshark"
KEYS_FILE = PROJECT_DIR / "keys"
PUBLIC_KEYS_FILE = PROJECT_DIR / "shared" / "public_keys.toml"


@dataclass(frozen=True)
class Host:
    machine: int
    ssh_target: str
    protocol_host: str
    instance: str | None = None
    zone: str | None = None


@dataclass(frozen=True)
class Node:
    id: int
    machine: int
    host: str
    port: int
    behavior: str


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not parsed > 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def network_percentage(value: str) -> float:
    parsed = float(value)
    if not 0 <= parsed < 100:
        raise argparse.ArgumentTypeError("must be in [0, 100)")
    return parsed


def port_number(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("must be in 1..=65535")
    return parsed


def behavior_assignment(value: str) -> tuple[int, str]:
    try:
        raw_id, behavior = value.split("=", 1)
        node_id = int(raw_id)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "must have the form NODE_ID=ok|byz1|byz2|silent"
        ) from error
    behavior = behavior.strip().lower()
    if node_id < 0 or behavior not in {"ok", "byz1", "byz2", "silent"}:
        raise argparse.ArgumentTypeError(
            "must have the form NODE_ID=ok|byz1|byz2|silent"
        )
    return node_id, behavior


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Deploy and run Sparse Bullshark on Linux machines over SSH or GCP"
        )
    )
    result.add_argument(
        "provider",
        nargs="?",
        choices=("ssh", "gcp"),
        default="ssh",
        help="ssh for an inventory file, or gcp to create/reuse Google Compute VMs",
    )

    cluster = result.add_argument_group("cluster")
    cluster.add_argument(
        "--hosts-file",
        type=Path,
        help=(
            "one machine per line: SSH_TARGET or SSH_TARGET,PROTOCOL_HOST; "
            "comments beginning with # are ignored"
        ),
    )
    cluster.add_argument(
        "--nodes",
        type=positive_int,
        help="number of processes (default: one per machine)",
    )
    cluster.add_argument("--base-port", type=port_number, default=8000)
    cluster.add_argument(
        "--behavior",
        action="append",
        type=behavior_assignment,
        default=[],
        metavar="NODE_ID=BEHAVIOR",
        help="override a node behavior; repeat for multiple nodes",
    )

    benchmark = result.add_argument_group("benchmark")
    benchmark.add_argument("--tx-size", type=positive_int, required=True)
    batch = benchmark.add_mutually_exclusive_group(required=True)
    batch.add_argument("--n-tx", type=positive_int)
    batch.add_argument(
        "--batch-size",
        type=positive_int,
        metavar="BYTES",
        help="maximum approximate serialized batch size; converted to --n-tx",
    )
    benchmark.add_argument(
        "--mode",
        choices=("sailfish", "prbc_sailfish"),
        default="prbc_sailfish",
    )
    benchmark.add_argument(
        "--input-rate",
        "--rate",
        type=nonnegative_int,
        default=0,
        help="aggregate transaction rate in tx/s (0 = unlimited)",
    )
    benchmark.add_argument(
        "--network-mbps",
        type=positive_float,
        help="per-node outbound network budget in Mbps; omitted disables shaping",
    )
    benchmark.add_argument(
        "--consensus-network-percent",
        type=network_percentage,
        default=20.0,
        help=(
            "network headroom reserved for both consensus planes when "
            "--network-mbps is set (default: 20)"
        ),
    )
    benchmark.add_argument(
        "--rbc", choices=("bracha", "signed_vote"), default="signed_vote"
    )
    benchmark.add_argument("--workers", type=positive_int, default=1)
    benchmark.add_argument("--faults", type=nonnegative_int, default=0)
    benchmark.add_argument("--duration", type=positive_int, default=60)
    benchmark.add_argument("--executions", type=positive_int, default=1)
    benchmark.add_argument("--no-prbc-sigs", action="store_true")
    benchmark.add_argument("--reduced-quorum", action="store_true")
    benchmark.add_argument(
        "--mempool", choices=("inline", "decoupled"), default="inline"
    )
    benchmark.add_argument(
        "--timeout",
        type=positive_int,
        default=500,
        metavar="MILLISECONDS",
        help="round timeout in milliseconds",
    )

    ssh = result.add_argument_group("SSH and deployment")
    ssh.add_argument(
        "--ssh-user",
        help="SSH username added to inventory entries that do not contain user@",
    )
    ssh.add_argument("--ssh-key", type=Path, help="private SSH key")
    ssh.add_argument(
        "--remote-dir",
        default="Sparse_Bullshark_cluster",
        help="deployment directory relative to the remote home directory",
    )
    ssh.add_argument("--ssh-timeout", type=positive_int, default=30)
    ssh.add_argument(
        "--startup-delay",
        type=nonnegative_int,
        default=5,
        metavar="SECONDS",
        help="lead time for the synchronized remote start",
    )
    ssh.add_argument(
        "--execution-timeout",
        type=positive_int,
        default=180,
        metavar="SECONDS",
    )
    ssh.add_argument(
        "--parallelism",
        type=positive_int,
        help="maximum simultaneous host operations (default: all active hosts)",
    )
    ssh.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_BINARY,
        help="Linux release binary to deploy",
    )
    ssh.add_argument(
        "--wsl-distro",
        default="Ubuntu-24.04",
        help=(
            "WSL distribution used to build the Linux binary when this script "
            "is launched by Windows Python"
        ),
    )
    ssh.add_argument("--skip-build", action="store_true")
    ssh.add_argument("--build-jobs", type=positive_int)
    ssh.add_argument(
        "--build-swap-gb",
        type=nonnegative_int,
        default=0,
        help="accepted for command compatibility; local WSL builds do not provision swap",
    )
    ssh.add_argument(
        "--skip-deploy",
        action="store_true",
        help="reuse files already installed in --remote-dir",
    )
    ssh.add_argument(
        "--deploy-only", action="store_true", help="deploy but do not start nodes"
    )
    ssh.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and print assignments without building, copying, or connecting",
    )

    output = result.add_argument_group("output")
    output.add_argument(
        "--output",
        type=Path,
        default=Path("cluster-results"),
        help="parent directory for timestamped run artifacts",
    )
    output.add_argument("--logs", action="store_true", help="print node stderr")

    gcp = result.add_argument_group("Google Cloud infrastructure")
    gcp.add_argument("--project", help="Google Cloud project id")
    gcp.add_argument("--machines", type=positive_int)
    gcp.add_argument("--machine-prefix", default="sailfish-node")
    gcp.add_argument(
        "--regions",
        default="europe-west4",
        help="comma-separated expected regions; used to validate existing placements",
    )
    gcp.add_argument("--network", default="bft-network")
    gcp.add_argument("--subnet", default="bft-subnet")
    gcp.add_argument("--subnet-range", default="10.10.0.0/24")
    gcp.add_argument("--machine-type", default="n2-highcpu-2")
    gcp.add_argument("--image-family", default="ubuntu-2604-lts-amd64")
    gcp.add_argument("--image-project", default="ubuntu-os-cloud")
    gcp.add_argument("--boot-disk-size", default="10GB")
    gcp.add_argument("--boot-disk-type", default="pd-balanced")
    gcp.add_argument("--network-tag", default="bft-node")
    gcp.add_argument(
        "--reuse-instances",
        action="store_true",
        help="reuse matching VMs and create any requested VMs that are missing",
    )
    gcp.add_argument("--ssh-source-range")
    gcp.add_argument("--force", action="store_true")
    gcp.add_argument("--keep-machines-running", action="store_true")
    gcp.add_argument(
        "--ssh-ready-timeout",
        type=positive_int,
        default=600,
        metavar="SECONDS",
        help="time allowed for newly created or started GCP VMs to accept SSH",
    )
    return result


def validate_remote_dir(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("--remote-dir must be a safe path relative to the remote home")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        raise ValueError("--remote-dir contains unsupported characters")
    return value.rstrip("/")


def read_hosts(path: Path, ssh_user: str | None) -> list[Host]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"cannot read hosts file {path}: {error}") from error

    parsed: list[tuple[str, str]] = []
    for line_number, line in enumerate(lines, 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        fields = next(csv.reader([content], skipinitialspace=True))
        if len(fields) not in {1, 2} or any(not field.strip() for field in fields):
            raise ValueError(
                f"{path}:{line_number}: expected SSH_TARGET or SSH_TARGET,PROTOCOL_HOST"
            )
        ssh_target = fields[0].strip()
        protocol_host = (
            fields[1].strip() if len(fields) == 2 else ssh_target.rsplit("@", 1)[-1]
        )
        if ssh_user and "@" not in ssh_target:
            ssh_target = f"{ssh_user}@{ssh_target}"
        parsed.append((ssh_target, protocol_host))

    if not parsed:
        raise ValueError(f"hosts file {path} contains no machines")
    if len({item[0] for item in parsed}) != len(parsed):
        raise ValueError("hosts file contains duplicate SSH targets")
    return [Host(index, ssh_target, protocol_host) for index, (ssh_target, protocol_host) in enumerate(parsed)]


def find_gcloud() -> str:
    candidates = ("gcloud.cmd", "gcloud") if os.name == "nt" else ("gcloud",)
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    raise ValueError("Google Cloud CLI was not found; install and authenticate gcloud")


def gcloud_json(args: argparse.Namespace) -> list[dict]:
    prefix_filter = f"name~'^{args.machine_prefix}-[0-9]+$'"
    result = subprocess.run(
        [
            args.gcloud,
            "compute",
            "instances",
            "list",
            f"--project={args.project}",
            f"--filter={prefix_filter}",
            "--format=json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, list):
        raise RuntimeError("gcloud returned an invalid instance inventory")
    return parsed


def instance_zone(record: dict) -> str:
    return str(record.get("zone", "")).rsplit("/", 1)[-1]


def configured_gcp_regions(args: argparse.Namespace) -> list[str]:
    regions = [region.strip() for region in args.regions.split(",")]
    if not regions or any(
        not region
        or re.fullmatch(r"[a-z](?:[a-z0-9-]*[a-z0-9])?", region) is None
        for region in regions
    ):
        raise ValueError("--regions must be a comma-separated list of GCP regions")
    if len(set(regions)) != len(regions):
        raise ValueError("--regions must not contain duplicates")
    return regions


def gcloud_exists(args: argparse.Namespace, command: list[str]) -> bool:
    result = subprocess.run(
        [args.gcloud, *command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def gcloud_object(args: argparse.Namespace, command: list[str]) -> dict:
    result = subprocess.run(
        [args.gcloud, *command, "--format=json"],
        check=True,
        capture_output=True,
        text=True,
    )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise RuntimeError("gcloud returned invalid JSON")
    return parsed


def regional_subnets(args: argparse.Namespace) -> dict[str, tuple[str, str]]:
    try:
        base = ipaddress.ip_network(args.subnet_range, strict=True)
    except ValueError as error:
        raise ValueError("--subnet-range must be a network CIDR") from error
    result = {}
    for offset, region in enumerate(configured_gcp_regions(args)):
        address = int(base.network_address) + offset * base.num_addresses
        try:
            network = ipaddress.ip_network((address, base.prefixlen))
        except ValueError as error:
            raise ValueError("--subnet-range cannot cover all requested regions") from error
        name = args.subnet if offset == 0 else f"{args.subnet}-{region}"
        if len(name) > 63:
            raise ValueError(f"derived subnet name is too long: {name}")
        result[region] = (name, str(network))
    return result


def available_gcp_zones(
    args: argparse.Namespace, regions: list[str]
) -> dict[str, list[str]]:
    result = subprocess.run(
        [
            args.gcloud,
            "compute",
            "zones",
            "list",
            f"--project={args.project}",
            "--filter=status=UP",
            "--format=json(name,region,status)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    records = json.loads(result.stdout)
    by_region: dict[str, list[str]] = {region: [] for region in regions}
    for record in records:
        region = str(record.get("region", "")).rsplit("/", 1)[-1]
        name = record.get("name")
        if region in by_region and name:
            by_region[region].append(str(name))
    for region in regions:
        by_region[region].sort()
        if not by_region[region]:
            raise RuntimeError(f"GCP returned no available zones in {region}")
    return by_region


def ensure_gcp_firewall(
    args: argparse.Namespace,
    name: str,
    source_ranges: set[str],
    rules: str,
) -> None:
    describe = [
        "compute",
        "firewall-rules",
        "describe",
        name,
        f"--project={args.project}",
    ]
    if gcloud_exists(args, describe):
        existing = gcloud_object(args, describe)
        combined = sorted(source_ranges | set(existing.get("sourceRanges") or []))
        if combined != sorted(existing.get("sourceRanges") or []):
            subprocess.run(
                [
                    args.gcloud,
                    "compute",
                    "firewall-rules",
                    "update",
                    name,
                    f"--project={args.project}",
                    f"--source-ranges={','.join(combined)}",
                    "--quiet",
                ],
                check=True,
            )
        return
    subprocess.run(
        [
            args.gcloud,
            "compute",
            "firewall-rules",
            "create",
            name,
            f"--project={args.project}",
            f"--network={args.network}",
            "--direction=INGRESS",
            "--action=ALLOW",
            f"--source-ranges={','.join(sorted(source_ranges))}",
            f"--rules={rules}",
            f"--target-tags={args.network_tag}",
            "--quiet",
        ],
        check=True,
    )


def ensure_gcp_infrastructure(args: argparse.Namespace) -> None:
    network_describe = [
        "compute",
        "networks",
        "describe",
        args.network,
        f"--project={args.project}",
    ]
    if not gcloud_exists(args, network_describe):
        print(f"Creating GCP network {args.network}...")
        subprocess.run(
            [
                args.gcloud,
                "compute",
                "networks",
                "create",
                args.network,
                f"--project={args.project}",
                "--subnet-mode=custom",
                "--quiet",
            ],
            check=True,
        )

    subnets = regional_subnets(args)
    for region, (name, cidr) in subnets.items():
        describe = [
            "compute",
            "networks",
            "subnets",
            "describe",
            name,
            f"--project={args.project}",
            f"--region={region}",
        ]
        if not gcloud_exists(args, describe):
            print(f"Creating subnet {name} ({cidr}) in {region}...")
            subprocess.run(
                [
                    args.gcloud,
                    "compute",
                    "networks",
                    "subnets",
                    "create",
                    name,
                    f"--project={args.project}",
                    f"--network={args.network}",
                    f"--region={region}",
                    f"--range={cidr}",
                    "--quiet",
                ],
                check=True,
            )

    ensure_gcp_firewall(
        args,
        "allow-bft-internal",
        {cidr for _, cidr in subnets.values()},
        "tcp,udp,icmp",
    )
    ssh_sources = {"35.235.240.0/20"}
    if args.ssh_source_range:
        try:
            ssh_sources.add(str(ipaddress.ip_network(args.ssh_source_range, strict=False)))
        except ValueError as error:
            raise ValueError("--ssh-source-range must be a CIDR") from error
    ensure_gcp_firewall(
        args,
        "allow-sparse-bullshark-iap-ssh",
        ssh_sources,
        "tcp:22",
    )


def create_gcp_instances(
    args: argparse.Namespace,
    names: list[str],
    desired_regions: dict[str, str],
    zones_by_region: dict[str, list[str]],
) -> None:
    subnets = regional_subnets(args)

    def create_one(name: str) -> tuple[str, str]:
        region = desired_regions[name]
        candidates = zones_by_region[region]
        machine_index = int(name.rsplit("-", 1)[-1])
        region_position = machine_index // len(configured_gcp_regions(args))
        offset = region_position % len(candidates)
        ordered_zones = candidates[offset:] + candidates[:offset]
        failures = []
        for zone in ordered_zones:
            command = [
                args.gcloud,
                "compute",
                "instances",
                "create",
                name,
                f"--project={args.project}",
                f"--zone={zone}",
                f"--machine-type={args.machine_type}",
                f"--image-family={args.image_family}",
                f"--image-project={args.image_project}",
                f"--boot-disk-size={args.boot_disk_size}",
                f"--boot-disk-type={args.boot_disk_type}",
                f"--network={args.network}",
                f"--subnet={subnets[region][0]}",
                f"--tags={args.network_tag}",
                "--no-address",
                "--quiet",
            ]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode == 0:
                return name, zone
            detail = (completed.stderr or completed.stdout).strip()
            failures.append(f"{zone}: {detail}")
            retryable = any(
                marker in detail
                for marker in (
                    "ZONE_RESOURCE_POOL_EXHAUSTED",
                    "resource_availability",
                    "does not have enough resources available",
                    "MACHINE_TYPE_UNSUPPORTED",
                )
            )
            if not retryable:
                break
        concise = failures[-1].splitlines()[-1] if failures else "unknown error"
        raise RuntimeError(
            f"could not create {name} in any usable {region} zone: {concise}"
        )

    print(
        f"Creating {len(names)} missing VM(s) across all available zones "
        "with capacity fallback..."
    )
    failures = []
    workers = min(args.parallelism or 8, len(names))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(create_one, name): name for name in names}
        for future in as_completed(futures):
            name = futures[future]
            try:
                _, zone = future.result()
                print(f"[OK] Created {name} in {zone}")
            except Exception as error:
                failures.append(f"{name}: {error}")
    if failures:
        raise RuntimeError(
            f"failed to create {len(failures)}/{len(names)} VM(s): "
            + "; ".join(failures[:3])
        )


def discover_gcp_hosts(args: argparse.Namespace, start_instances: bool) -> list[Host]:
    if not args.project or not args.machines:
        raise ValueError("gcp mode requires --project and --machines")

    desired_names = [f"{args.machine_prefix}-{index}" for index in range(args.machines)]
    regions = configured_gcp_regions(args)
    zones_by_region = available_gcp_zones(args, regions)
    desired_regions = {
        name: regions[index % len(regions)]
        for index, name in enumerate(desired_names)
    }
    inventory = {record.get("name"): record for record in gcloud_json(args)}
    missing = [name for name in desired_names if name not in inventory]
    existing = [name for name in desired_names if name in inventory]
    if existing and not args.reuse_instances:
        raise ValueError(
            "target GCP instance(s) already exist: "
            + ", ".join(existing[:8])
            + "; add --reuse-instances or choose another --machine-prefix"
        )

    misplaced = []
    for name in existing:
        zone = instance_zone(inventory[name])
        actual_region = zone.rsplit("-", 1)[0]
        if actual_region != desired_regions[name]:
            misplaced.append(
                f"{name} ({zone}, expected region {desired_regions[name]})"
            )
    if misplaced:
        raise ValueError("instances in unexpected zones: " + ", ".join(misplaced[:8]))

    if not args.dry_run:
        ensure_gcp_infrastructure(args)

    if missing and args.dry_run:
        by_region: dict[str, int] = defaultdict(int)
        for name in missing:
            by_region[desired_regions[name]] += 1
        plan = ", ".join(
            f"{count} in {region} across {len(zones_by_region[region])} zone(s)"
            for region, count in by_region.items()
        )
        print(f"DRY RUN: would create {len(missing)} GCP VM(s): {plan}.")
    elif missing:
        args.gcp_cleanup_armed = True
        create_gcp_instances(args, missing, desired_regions, zones_by_region)
        inventory = {record.get("name"): record for record in gcloud_json(args)}
        still_missing = [name for name in desired_names if name not in inventory]
        if still_missing:
            raise RuntimeError(
                "GCP did not return newly created instance(s): "
                + ", ".join(still_missing[:8])
            )

    stopped_by_zone: dict[str, list[str]] = defaultdict(list)
    for name in existing:
        record = inventory[name]
        if record.get("status") != "RUNNING":
            stopped_by_zone[instance_zone(record)].append(name)
    if stopped_by_zone and start_instances:
        args.gcp_cleanup_armed = True
        for zone, names in stopped_by_zone.items():
            print(f"Starting {len(names)} existing VM(s) in {zone}...")
            subprocess.run(
                [
                    args.gcloud,
                    "compute",
                    "instances",
                    "start",
                    *names,
                    f"--project={args.project}",
                    f"--zone={zone}",
                    "--quiet",
                ],
                check=True,
            )
        inventory = {record.get("name"): record for record in gcloud_json(args)}

    hosts = []
    for machine, name in enumerate(desired_names):
        record = inventory.get(name)
        if record is None and args.dry_run:
            hosts.append(
                Host(
                    machine=machine,
                    ssh_target=name,
                    protocol_host="assigned-after-create",
                    instance=name,
                    zone=zones_by_region[desired_regions[name]][0],
                )
            )
            continue
        if record is None:
            raise RuntimeError(f"no GCP inventory record was returned for {name}")
        interfaces = record.get("networkInterfaces") or []
        internal_ip = interfaces[0].get("networkIP") if interfaces else None
        if not internal_ip:
            raise RuntimeError(f"no private IPv4 address was returned for {name}")
        hosts.append(
            Host(
                machine=machine,
                ssh_target=name,
                protocol_host=internal_ip,
                instance=name,
                zone=instance_zone(record),
            )
        )
    return hosts


def gcp_ssh_is_ready(args: argparse.Namespace, host: Host) -> bool:
    environment = os.environ.copy()
    if os.name == "nt":
        # Fresh GCP VMs have new SSH host keys.  PuTTY's batch mode rejects an
        # uncached key before the guest can be considered ready, so let gcloud
        # perform its normal one-time host-key bootstrap during this probe.
        # Deployment and experiment commands continue to use batch mode after
        # the key has been cached, with stdin left untouched for `bash -s`.
        environment["CLOUDSDK_SSH_PUTTY_FORCE_CONNECT"] = "true"
    try:
        result = subprocess.run(
            remote_command_arguments(host, args, "true", batch_mode=False),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=min(args.ssh_timeout + 10, 60),
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def wait_for_gcp_ssh(args: argparse.Namespace, hosts: list[Host]) -> None:
    pending = {host.instance: host for host in hosts}
    deadline = time.monotonic() + args.ssh_ready_timeout
    workers = min(args.parallelism or 8, len(hosts))
    while pending:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(gcp_ssh_is_ready, args, host): name
                for name, host in pending.items()
            }
            for future in as_completed(futures):
                name = futures[future]
                if future.result():
                    pending.pop(name, None)
                    print(f"[OK] SSH ready: {name}")
        if not pending:
            return
        if time.monotonic() >= deadline:
            names = ", ".join(list(pending)[:8])
            raise RuntimeError(f"timed out waiting for GCP SSH: {names}")
        print(f"Waiting for SSH on {len(pending)} GCP VM(s)...")
        time.sleep(5)


def stop_gcp_hosts(args: argparse.Namespace, hosts: list[Host]) -> None:
    by_zone: dict[str, list[str]] = defaultdict(list)
    for host in hosts:
        if host.instance and host.zone:
            by_zone[host.zone].append(host.instance)
    def stop_zone(zone: str, names: list[str]) -> tuple[str, int]:
        result = subprocess.run(
            [
                args.gcloud,
                "compute",
                "instances",
                "stop",
                *names,
                f"--project={args.project}",
                f"--zone={zone}",
                "--quiet",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        return zone, len(names)

    with ThreadPoolExecutor(max_workers=len(by_zone)) as executor:
        futures = {
            executor.submit(stop_zone, zone, names): zone
            for zone, names in by_zone.items()
        }
        failures = []
        for future in as_completed(futures):
            try:
                zone, count = future.result()
                print(f"[OK] Stopped {count} instance(s) in {zone}")
            except Exception as error:
                failures.append(f"{futures[future]}: {error}")
    if failures:
        raise RuntimeError("failed to stop GCP VMs: " + "; ".join(failures))


def stop_gcp_if_needed(args: argparse.Namespace) -> None:
    hosts = getattr(args, "active_gcp_hosts", None)
    if (
        args.provider == "gcp"
        and not hosts
        and getattr(args, "gcp_cleanup_armed", False)
    ):
        desired = {
            f"{args.machine_prefix}-{index}" for index in range(args.machines or 0)
        }
        records = [record for record in gcloud_json(args) if record.get("name") in desired]
        hosts = [
            Host(
                machine=index,
                ssh_target=str(record["name"]),
                protocol_host="",
                instance=str(record["name"]),
                zone=instance_zone(record),
            )
            for index, record in enumerate(records)
        ]
    if (
        args.provider != "gcp"
        or args.keep_machines_running
        or not hosts
        or getattr(args, "gcp_stopped", False)
    ):
        return
    print("Stopping GCP protocol machines...")
    stop_gcp_hosts(args, hosts)
    args.gcp_stopped = True


def remote_command_arguments(
    host: Host,
    args: argparse.Namespace,
    remote_command: str,
    *,
    batch_mode: bool = True,
) -> list[str]:
    if args.provider == "gcp":
        command = [
            args.gcloud,
            "compute",
            "ssh",
            host.instance,
            f"--project={args.project}",
            f"--zone={host.zone}",
            "--tunnel-through-iap",
            "--quiet",
        ]
        if batch_mode:
            command.append(
                "--ssh-flag=-batch"
                if os.name == "nt"
                else "--ssh-flag=-oBatchMode=yes"
            )
        command.append(f"--command={remote_command}")
        return command
    return [
        "ssh",
        *ssh_options(args),
        host.ssh_target,
        "bash",
        "-lc",
        remote_command,
    ]


def copy_command_arguments(
    host: Host, args: argparse.Namespace, sources: list[str], destination: str
) -> list[str]:
    if args.provider == "gcp":
        return [
            args.gcloud,
            "compute",
            "scp",
            *sources,
            f"{host.instance}:{destination}",
            f"--project={args.project}",
            f"--zone={host.zone}",
            "--tunnel-through-iap",
            "--quiet",
        ]
    return ["scp", *ssh_options(args), *sources, f"{host.ssh_target}:{destination}"]


def read_private_keys(path: Path, nodes: int) -> list[str]:
    try:
        keys = [
            line.strip().split(":", 1)[0]
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except OSError as error:
        raise ValueError(f"cannot read private keys from {path}: {error}") from error
    if len(keys) < nodes:
        raise ValueError(f"{path} contains {len(keys)} private keys but {nodes} are required")
    return keys[:nodes]


def validate_public_keys(path: Path, nodes: int) -> None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"cannot read public keys from {path}: {error}") from error
    configured = {
        int(match.group(1))
        for match in re.finditer(r"^\s*\[\s*[\"']?(\d+)[\"']?\s*\]\s*$", content, re.MULTILINE)
    }
    missing = [node_id for node_id in range(nodes) if node_id not in configured]
    if missing:
        preview = ", ".join(map(str, missing[:8]))
        suffix = "..." if len(missing) > 8 else ""
        raise ValueError(f"{path} is missing public keys for node(s) {preview}{suffix}")


def assign_nodes(
    hosts: list[Host], count: int, base_port: int, behavior_overrides: dict[int, str]
) -> list[Node]:
    local_counts = [0] * len(hosts)
    nodes = []
    for node_id in range(count):
        machine = node_id % len(hosts)
        port = base_port + local_counts[machine]
        if port > 65535:
            raise ValueError("node assignment exceeds TCP port 65535")
        local_counts[machine] += 1
        nodes.append(
            Node(
                id=node_id,
                machine=machine,
                host=hosts[machine].protocol_host,
                port=port,
                behavior=behavior_overrides.get(node_id, "ok"),
            )
        )
    return nodes


def nodes_csv(nodes: list[Node]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("id", "host", "port", "behavior"))
    for node in nodes:
        writer.writerow((node.id, node.host, node.port, node.behavior))
    return output.getvalue()


def invocation_record(args: argparse.Namespace, nodes: list[Node]) -> dict:
    runtime_only = {
        "active_gcp_hosts",
        "behavior",
        "gcloud",
        "gcp_cleanup_armed",
        "gcp_stopped",
    }
    invocation = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in vars(args).items()
        if key not in runtime_only
    }
    invocation["behavior"] = [
        f"{node_id}={behavior}" for node_id, behavior in args.behavior
    ]
    invocation["assignments"] = [asdict(node) for node in nodes]
    return invocation


def group_nodes(nodes: list[Node]) -> dict[int, list[Node]]:
    result: dict[int, list[Node]] = defaultdict(list)
    for node in nodes:
        result[node.machine].append(node)
    return dict(result)


def ssh_options(args: argparse.Namespace) -> list[str]:
    options = [
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={args.ssh_timeout}",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
    ]
    if args.ssh_key:
        options[0:0] = ["-i", str(args.ssh_key.expanduser().resolve())]
    return options


async def command(
    arguments: list[str], timeout_seconds: int, input_bytes: bytes | None = None
) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.PIPE if input_bytes is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(input=input_bytes), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return -1, "", f"timed out after {timeout_seconds}s"
    return (
        process.returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


async def deploy_host(
    host: Host,
    args: argparse.Namespace,
    binary: Path,
    generated_csv: Path,
    public_keys: Path,
    semaphore: asyncio.Semaphore,
) -> None:
    async with semaphore:
        remote_root = args.remote_dir
        mkdir = f'mkdir -p "$HOME/{remote_root}/shared"'
        rc, _, stderr = await command(
            remote_command_arguments(host, args, mkdir),
            args.ssh_timeout + 10,
        )
        if rc != 0:
            raise RuntimeError(f"{host.ssh_target}: cannot create deployment: {stderr.strip()}")

        copies = (
            ([str(binary)], f"{remote_root}/"),
            (
                [str(generated_csv), str(public_keys)],
                f"{remote_root}/shared/",
            ),
        )
        for sources, destination in copies:
            rc, _, stderr = await command(
                copy_command_arguments(host, args, sources, destination),
                args.ssh_timeout + 120,
            )
            if rc != 0:
                raise RuntimeError(f"{host.ssh_target}: SCP failed: {stderr.strip()}")

        binary_name = binary.name
        chmod = f'chmod 700 "$HOME/{remote_root}/{binary_name}"'
        rc, _, stderr = await command(
            remote_command_arguments(host, args, chmod),
            args.ssh_timeout + 10,
        )
        if rc != 0:
            raise RuntimeError(f"{host.ssh_target}: chmod failed: {stderr.strip()}")
        print(f"[OK] Deployed machine{host.machine} ({host.ssh_target})")


def remote_script(
    hosted_nodes: list[Node],
    keys: list[str],
    args: argparse.Namespace,
    binary_name: str,
    run_id: str,
    start_at_ms: int,
) -> str:
    remote_binary = f'$HOME/{args.remote_dir}/{binary_name}'
    result_dir = f"/tmp/sparse-bullshark-{run_id}"
    quote = shlex.quote
    lines = [
        "#!/usr/bin/env bash",
        "set -u",
        f'cd "$HOME/{args.remote_dir}"',
        f'pkill -f -- "{remote_binary}" 2>/dev/null || true',
        f"rm -rf -- {quote(result_dir)}",
        f"mkdir -p -- {quote(result_dir)}",
        f"export PROTOCOL={quote(args.mode)}",
        f"export INPUT_RATE={quote(str(args.input_rate))}",
        f"export ROUND_TIMEOUT_MS={quote(str(args.timeout))}",
        f"export RBC_MODE={quote(args.rbc)}",
        f"export PRBC_SIGS={'off' if args.no_prbc_sigs else 'on'}",
        f"export REDUCED_QUORUM={'on' if args.reduced_quorum else 'off'}",
        f"export MEMPOOL_MODE={quote(args.mempool)}",
        "export RUST_LOG=warn",
    ]
    if args.network_mbps is not None:
        lines.extend(
            [
                f"export NETWORK_MBPS={quote(str(args.network_mbps))}",
                "export CONSENSUS_NETWORK_PERCENT="
                f"{quote(str(args.consensus_network_percent))}",
            ]
        )
    for node in hosted_nodes:
        lines.append(f"export PRIVATE_KEY_{node.id}={quote(keys[node.id])}")

    lines.extend(
        [
            f"start_at_ms={start_at_ms}",
            "now_ms=$(date +%s%3N)",
            "if (( now_ms < start_at_ms )); then",
            "  delay_ms=$((start_at_ms - now_ms))",
            "  printf -v delay_seconds '%d.%03d' $((delay_ms / 1000)) $((delay_ms % 1000))",
            '  sleep "$delay_seconds"',
            "fi",
            "pids=()",
            "node_ids=()",
        ]
    )
    for node in hosted_nodes:
        stdout_path = f"{result_dir}/node{node.id}.out"
        stderr_path = f"{result_dir}/node{node.id}.err"
        lines.append(
            f'"{remote_binary}" {node.id} {args.tx_size} {args.n_tx} '
            f">{quote(stdout_path)} 2>{quote(stderr_path)} &"
        )
        lines.append("pids+=($!)")
        lines.append(f"node_ids+=({node.id})")

    lines.extend(
        [
            "status=0",
            'for pid in "${pids[@]}"; do',
            '  wait "$pid" || status=1',
            "done",
        ]
    )
    for node in hosted_nodes:
        lines.extend(
            [
                f'echo "__SB_NODE_{node.id}_STDOUT_START__"',
                f"cat -- {quote(f'{result_dir}/node{node.id}.out')}",
                f'echo "__SB_NODE_{node.id}_STDOUT_END__"',
                f'echo "__SB_NODE_{node.id}_STDERR_START__"',
                f"cat -- {quote(f'{result_dir}/node{node.id}.err')}",
                f'echo "__SB_NODE_{node.id}_STDERR_END__"',
            ]
        )
    lines.append("exit $status")
    return "\n".join(lines) + "\n"


def remote_collection_script(hosted_nodes: list[Node], run_id: str) -> str:
    """Read completed node logs after the original SSH tunnel was interrupted."""
    result_dir = f"/tmp/sparse-bullshark-{run_id}"
    quote = shlex.quote
    lines = ["#!/usr/bin/env bash", "set -u"]
    for node in hosted_nodes:
        lines.extend(
            [
                f'echo "__SB_NODE_{node.id}_STDOUT_START__"',
                f"cat -- {quote(f'{result_dir}/node{node.id}.out')} 2>/dev/null || true",
                f'echo "__SB_NODE_{node.id}_STDOUT_END__"',
                f'echo "__SB_NODE_{node.id}_STDERR_START__"',
                f"cat -- {quote(f'{result_dir}/node{node.id}.err')} 2>/dev/null || true",
                f'echo "__SB_NODE_{node.id}_STDERR_END__"',
            ]
        )
    return "\n".join(lines) + "\n"


async def run_host(
    host: Host,
    hosted_nodes: list[Node],
    keys: list[str],
    args: argparse.Namespace,
    binary_name: str,
    run_id: str,
    start_at_ms: int,
    semaphore: asyncio.Semaphore,
) -> tuple[Host, int, str, str]:
    script = remote_script(
        hosted_nodes, keys, args, binary_name, run_id, start_at_ms
    )
    async with semaphore:
        rc, stdout, stderr = await command(
            remote_command_arguments(host, args, "bash -s"),
            args.execution_timeout,
            script.encode("utf-8"),
        )
    return host, rc, stdout, stderr


def has_complete_node_results(hosted_nodes: list[Node], combined: str) -> bool:
    parsed_stdout, _ = split_outputs(combined)
    for node in hosted_nodes:
        config, result = parse_result(parsed_stdout.get(node.id, ""))
        if not config or not result:
            return False
    return True


async def recover_host_outputs(
    host: Host,
    hosted_nodes: list[Node],
    args: argparse.Namespace,
    run_id: str,
    semaphore: asyncio.Semaphore,
    attempts: int = 4,
) -> tuple[str, str] | None:
    """Retry result collection without rerunning the experiment."""
    script = remote_collection_script(hosted_nodes, run_id)
    diagnostics: list[str] = []
    for attempt in range(1, attempts + 1):
        async with semaphore:
            rc, stdout, stderr = await command(
                remote_command_arguments(host, args, "bash -s"),
                args.ssh_timeout + 30,
                script.encode("utf-8"),
            )
        if has_complete_node_results(hosted_nodes, stdout):
            return stdout, "\n".join(diagnostics + [stderr]).strip()
        diagnostics.append(
            f"result collection attempt {attempt}/{attempts} exited with {rc}: "
            f"{stderr.strip()}"
        )
        if attempt < attempts:
            await asyncio.sleep(min(2 * attempt, 5))
    return None


def split_outputs(combined: str) -> tuple[dict[int, str], dict[int, str]]:
    streams: dict[str, dict[int, str]] = {"STDOUT": {}, "STDERR": {}}
    current: tuple[int, str] | None = None
    buffer: list[str] = []
    marker = re.compile(r"^__SB_NODE_(\d+)_(STDOUT|STDERR)_(START|END)__$")
    for line in combined.splitlines():
        match = marker.match(line)
        if not match:
            if current is not None:
                buffer.append(line)
            continue
        node_id, stream, boundary = int(match.group(1)), match.group(2), match.group(3)
        if boundary == "START":
            current = (node_id, stream)
            buffer = []
        elif current == (node_id, stream):
            streams[stream][node_id] = "\n".join(buffer).strip()
            current = None
            buffer = []
    return streams["STDOUT"], streams["STDERR"]


def parse_result(output: str) -> tuple[dict[str, str], dict[str, str]]:
    config: dict[str, str] = {}
    results: dict[str, str] = {}
    section: str | None = None
    for line in output.splitlines():
        if "+ CONFIG:" in line:
            section = "config"
        elif "+ RESULTS:" in line:
            section = "results"
        elif section:
            match = re.match(r"  (.+?):\s{2,}(.+)", line)
            if match:
                target = config if section == "config" else results
                target[match.group(1).strip()] = match.group(2).strip()
    return config, results


def medians(results: list[dict[str, str]]) -> dict[str, str]:
    aggregated: dict[str, str] = {}
    for key in results[0]:
        values: list[float] = []
        unit = ""
        for result in results:
            match = re.match(r"^([\d.]+)\s*(.*)", result.get(key, ""))
            if match:
                values.append(float(match.group(1)))
                unit = match.group(2).strip()
        if not values:
            aggregated[key] = results[0].get(key, "")
            continue
        median = statistics.median(values)
        first = results[0][key].split()[0]
        rendered = f"{median:.1f}" if "." in first else str(int(round(median)))
        aggregated[key] = f"{rendered} {unit}".strip()
    return aggregated


def summary_text(
    config: dict[str, str], results: dict[str, str], node_count: int
) -> str:
    lines = [f"(Median of {node_count} node(s))", "", "+ CONFIG:"]
    lines.extend(f"  {(key + ':'):<24} {value}" for key, value in config.items())
    lines.extend(("", "+ RESULTS:"))
    lines.extend(f"  {(key + ':'):<24} {value}" for key, value in results.items())
    return "\n".join(lines) + "\n"


def print_dry_run(hosts: list[Host], nodes: list[Node], args: argparse.Namespace) -> None:
    grouped = group_nodes(nodes)
    print("DRY RUN: no build, deployment, SSH connection, or remote process will occur.")
    print(f"Machines: {len(grouped)} / {len(hosts)} configured")
    print(f"Nodes:    {len(nodes)}")
    print(f"Protocol: {args.mode}")
    print(f"Rate:     {args.input_rate if args.input_rate else 'unlimited'} tx/s")
    if args.provider == "gcp":
        print(f"VM type:  {args.machine_type}")
    print("Assignments:")
    for machine, hosted in grouped.items():
        host = hosts[machine]
        descriptions = ", ".join(
            f"node{node.id}@{node.host}:{node.port}({node.behavior})" for node in hosted
        )
        print(f"  machine{machine} {host.ssh_target}: {descriptions}")


def wsl_project_location(requested_distro: str) -> tuple[str, str]:
    """Return (distribution, Linux project path) for a Windows controller."""
    project = str(PROJECT_DIR)
    match = re.match(
        r"^\\\\wsl(?:\.localhost|\$)\\([^\\]+)\\(.*)$",
        project,
        re.IGNORECASE,
    )
    if match:
        distro = match.group(1)
        linux_path = "/" + match.group(2).replace("\\", "/")
        return distro, linux_path

    converted = subprocess.run(
        ["wsl.exe", "-d", requested_distro, "--", "wslpath", "-a", project],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not converted:
        raise ValueError(f"could not convert project path to WSL: {project}")
    return requested_distro, converted


def build_binary(args: argparse.Namespace) -> Path:
    binary = args.binary.expanduser()
    if not binary.is_absolute():
        binary = (PROJECT_DIR / binary).resolve()
    if not args.skip_build:
        cargo_arguments = ["cargo", "build", "--release"]
        if args.build_jobs:
            cargo_arguments.extend(("-j", str(args.build_jobs)))
        if os.name == "nt":
            distro, linux_project = wsl_project_location(args.wsl_distro)
            build_command = (
                f"cd {shlex.quote(linux_project)} && "
                + shlex.join(cargo_arguments)
            )
            subprocess.run(
                ["wsl.exe", "-d", distro, "--", "bash", "-ic", build_command],
                check=True,
            )
        else:
            subprocess.run(
                cargo_arguments, cwd=PROJECT_DIR, check=True
            )
    if not binary.is_file():
        raise ValueError(f"Linux binary not found: {binary}")
    return binary


async def execute(args: argparse.Namespace) -> int:
    args.remote_dir = validate_remote_dir(args.remote_dir)
    if args.batch_size is not None:
        vector_overhead = 8
        args.n_tx = max(1, (args.batch_size - vector_overhead) // args.tx_size)
        print(
            f"Converted --batch-size {args.batch_size} to --n-tx {args.n_tx} "
            f"(~{args.n_tx * args.tx_size} transaction bytes)."
        )
    if args.mode == "prbc_sailfish":
        # PRBC-Sailfish always orders digests and disseminates batches on its
        # separate data plane; keep the saved invocation consistent with the
        # actual Rust implementation.
        args.mempool = "decoupled"
    if args.workers != 1:
        raise ValueError("this project has one node process per authority; --workers must be 1")
    if args.faults != 0:
        raise ValueError(
            "--faults controls offline authorities in the reference runner; "
            "use repeated --behavior assignments in this project"
        )
    if args.duration != 60:
        raise ValueError("the current Rust binary has a fixed 60-second duration")
    if args.executions != 1:
        raise ValueError("the current cluster runner supports --executions 1")
    if args.ssh_key and not args.ssh_key.expanduser().is_file():
        raise ValueError(f"SSH key not found: {args.ssh_key}")

    if args.provider == "gcp":
        # The Windows SDK defaults ssh/putty_force_connect to true and injects
        # "y" into PuTTY's stdin. That corrupts scripts streamed to `bash -s`.
        # Override it only for this controller process and its gcloud children.
        if os.name == "nt":
            os.environ["CLOUDSDK_SSH_PUTTY_FORCE_CONNECT"] = "false"
        args.gcloud = find_gcloud()
        hosts = discover_gcp_hosts(args, start_instances=not args.dry_run)
        if not args.dry_run:
            args.active_gcp_hosts = hosts
            args.gcp_stopped = False
            wait_for_gcp_ssh(args, hosts)
    else:
        if args.hosts_file is None:
            raise ValueError("ssh mode requires --hosts-file")
        args.gcloud = None
        hosts = read_hosts(args.hosts_file.expanduser(), args.ssh_user)
    node_count = args.nodes or len(hosts)
    overrides = dict(args.behavior)
    invalid_overrides = sorted(node_id for node_id in overrides if node_id >= node_count)
    if invalid_overrides:
        raise ValueError(f"behavior override references absent node {invalid_overrides[0]}")
    nodes = assign_nodes(hosts, node_count, args.base_port, overrides)
    keys = read_private_keys(KEYS_FILE, node_count)
    validate_public_keys(PUBLIC_KEYS_FILE, node_count)
    grouped = group_nodes(nodes)
    active_hosts = [hosts[machine] for machine in sorted(grouped)]

    if args.dry_run:
        print_dry_run(hosts, nodes, args)
        return 0
    if args.deploy_only and args.skip_deploy:
        raise ValueError("--deploy-only cannot be combined with --skip-deploy")
    if args.provider == "ssh":
        for executable in ("ssh", "scp"):
            if shutil.which(executable) is None:
                raise ValueError(f"required command is not available: {executable}")

    binary = build_binary(args) if not args.skip_deploy else args.binary.expanduser()
    if not binary.is_absolute():
        binary = (PROJECT_DIR / binary).resolve()
    binary_name = binary.name
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result_root = args.output.expanduser() / run_id
    result_root.mkdir(parents=True, exist_ok=False)
    csv_content = nodes_csv(nodes)
    (result_root / "nodes.csv").write_text(csv_content, encoding="utf-8")
    invocation = invocation_record(args, nodes)
    (result_root / "invocation.json").write_text(
        json.dumps(invocation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    parallelism = args.parallelism or (
        min(8, len(active_hosts)) if args.provider == "gcp" else len(active_hosts)
    )
    deployment_semaphore = asyncio.Semaphore(parallelism)
    if not args.skip_deploy:
        with tempfile.TemporaryDirectory(prefix="sparse-bullshark-cluster-") as temporary:
            staging = Path(temporary)
            generated_csv = staging / "nodes.csv"
            generated_csv.write_text(csv_content, encoding="utf-8")
            staged_binary = staging / binary.name
            staged_public_keys = staging / PUBLIC_KEYS_FILE.name
            shutil.copy2(binary, staged_binary)
            shutil.copy2(PUBLIC_KEYS_FILE, staged_public_keys)
            await asyncio.gather(
                *(
                    deploy_host(
                        host,
                        args,
                        staged_binary,
                        generated_csv,
                        staged_public_keys,
                        deployment_semaphore,
                    )
                    for host in active_hosts
                )
            )
    if args.deploy_only:
        print(f"Deployment complete on {len(active_hosts)} machine(s).")
        print(f"Topology saved to {result_root / 'nodes.csv'}")
        return 0

    print("-" * 50)
    print(" STARTING CLUSTER EXPERIMENT")
    print("-" * 50)
    print(f"  Protocol:   {args.mode.replace('_', '-').upper()}")
    print(f"  Nodes:      {node_count}")
    print(f"  Machines:   {len(active_hosts)}")
    print(f"  Tx size:    {args.tx_size} B")
    print(f"  Tx/block:   {args.n_tx}")
    print(f"  Block bytes: ~{args.n_tx * args.tx_size} B")
    if args.batch_size is not None:
        print(f"  Requested:  {args.batch_size} B via --batch-size")
    print(f"  Input rate: {args.input_rate if args.input_rate else 'unlimited'} tx/s")
    if args.network_mbps is not None:
        print(
            f"  Network:    {args.network_mbps:g} Mbps/node, "
            f"{args.consensus_network_percent:g}% reserved for consensus"
        )
    print("-" * 50)

    start_at_ms = int((time.time() + args.startup_delay) * 1000)
    # Every authority must be launched concurrently. Limiting this phase to
    # deployment parallelism deadlocks the first group while it waits for
    # authorities that have not started yet.
    execution_semaphore = asyncio.Semaphore(len(active_hosts))
    machine_results = await asyncio.gather(
        *(
            run_host(
                host,
                grouped[host.machine],
                keys,
                args,
                binary_name,
                run_id,
                start_at_ms,
                execution_semaphore,
            )
            for host in active_hosts
        )
    )

    # A long-lived Windows gcloud/PuTTY tunnel can terminate after the remote
    # benchmark has already written complete files (commonly 0xC0000005 under
    # high tunnel concurrency). Reconnect with bounded concurrency and recover
    # those files before declaring the entire experiment unusable.
    incomplete_machine_results = [
        result
        for result in machine_results
        if not has_complete_node_results(grouped[result[0].machine], result[2])
    ]
    recovered_machine_stdout: dict[int, tuple[str, str]] = {}
    if incomplete_machine_results:
        print(
            f"Recovering results from {len(incomplete_machine_results)} "
            "interrupted SSH tunnel(s)..."
        )
        recovery_semaphore = asyncio.Semaphore(parallelism)
        recovery_results = await asyncio.gather(
            *(
                recover_host_outputs(
                    host,
                    grouped[host.machine],
                    args,
                    run_id,
                    recovery_semaphore,
                )
                for host, _, _, _ in incomplete_machine_results
            )
        )
        for original, recovered in zip(incomplete_machine_results, recovery_results):
            host, _, _, _ = original
            if recovered is not None:
                recovered_machine_stdout[host.machine] = recovered
                print(f"[OK] Recovered result files from machine{host.machine}")

    if recovered_machine_stdout:
        machine_results = [
            (
                host,
                rc,
                recovered_machine_stdout[host.machine][0],
                "\n".join(
                    part
                    for part in (stderr, recovered_machine_stdout[host.machine][1])
                    if part
                ),
            )
            if host.machine in recovered_machine_stdout
            else (host, rc, stdout, stderr)
            for host, rc, stdout, stderr in machine_results
        ]

    node_stdout: dict[int, str] = {}
    node_stderr: dict[int, str] = {}
    transport_failures = []
    for host, rc, stdout, stderr in machine_results:
        (result_root / f"machine{host.machine}.ssh.stderr").write_text(
            stderr, encoding="utf-8"
        )
        parsed_stdout, parsed_stderr = split_outputs(stdout)
        node_stdout.update(parsed_stdout)
        node_stderr.update(parsed_stderr)
        if rc != 0:
            transport_failures.append((host, rc, stderr.strip()))

    configs: list[dict[str, str]] = []
    results: list[dict[str, str]] = []
    complete_result_nodes: set[int] = set()
    for node in nodes:
        stdout = node_stdout.get(node.id, "")
        stderr = node_stderr.get(node.id, "")
        (result_root / f"node{node.id}.out").write_text(stdout + "\n", encoding="utf-8")
        (result_root / f"node{node.id}.err").write_text(stderr + "\n", encoding="utf-8")
        config, parsed = parse_result(stdout)
        if config and parsed:
            configs.append(config)
            results.append(parsed)
            complete_result_nodes.add(node.id)
        if args.logs and stderr:
            print(f"\n--- node{node.id} stderr ---")
            print(stderr)

    failed_hosts = []
    recovered_transports = 0
    for host, rc, detail in transport_failures:
        hosted_ids = {node.id for node in grouped[host.machine]}
        if hosted_ids.issubset(complete_result_nodes):
            recovered_transports += 1
        else:
            failed_hosts.append((host, rc, detail))
            print(
                f"Warning: machine{host.machine} ({host.ssh_target}) exited with {rc}"
                + (f": {detail}" if detail else ""),
                file=sys.stderr,
            )
    if recovered_transports:
        print(
            f"Warning: {recovered_transports} Windows SSH tunnel process(es) "
            "returned nonzero after delivering complete node results; "
            "treating them as successful.",
            file=sys.stderr,
        )
    if len(results) != node_count:
        missing = sorted(set(range(node_count)) - complete_result_nodes)
        print(
            f"Error: parsed {len(results)}/{node_count} node result(s); "
            f"missing output from {missing or 'nodes with incomplete results'}",
            file=sys.stderr,
        )
        if results:
            partial_summary = summary_text(
                configs[0], medians(results), len(results)
            )
            partial_path = result_root / "summary.partial.txt"
            partial_path.write_text(partial_summary, encoding="utf-8")
            print(
                f"A clearly marked partial summary was saved to {partial_path}",
                file=sys.stderr,
            )
        print(f"Raw output is in {result_root}", file=sys.stderr)
        stop_gcp_if_needed(args)
        return 1

    summary = summary_text(configs[0], medians(results), len(results))
    print()
    print(summary, end="")
    (result_root / "summary.txt").write_text(summary, encoding="utf-8")
    print(f"Artifacts: {result_root}")
    stop_gcp_if_needed(args)
    return 1 if failed_hosts else 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return asyncio.run(execute(args))
    except KeyboardInterrupt:
        stop_gcp_if_needed(args)
        print("Interrupted.", file=sys.stderr)
        return 130
    except Exception as error:
        try:
            stop_gcp_if_needed(args)
        except Exception as cleanup_error:
            print(f"Warning: failed to stop GCP machines: {cleanup_error}", file=sys.stderr)
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
