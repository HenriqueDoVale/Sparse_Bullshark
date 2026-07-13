#!/usr/bin/env bash
# setup_cluster.sh — One-time cluster setup: generate nodes config, open firewall,
# and copy the binary + config files to every machine.
#
# Run from the Sparse_Bullshark project root on any machine with gcloud configured
# (Cloud Shell, your big machine, etc.).
#
# Usage:
#   bash setup_cluster.sh

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

ZONE="europe-west4-a"
BINARY="./target/release/sparse_bullshark"
NODES_PER_MACHINE=5

# Machine name → internal IP  (edit if your IPs change)
declare -A MACHINE_IPS=(
    ["node-0"]="10.164.0.12"
    ["node-1"]="10.164.0.6"
    ["node-2"]="10.164.0.11"
    ["node-3"]="10.164.0.8"
    ["node-4"]="10.164.0.9"
    ["node-5"]="10.164.0.10"
)
MACHINES=("node-0" "node-1" "node-2" "node-3" "node-4" "node-5")

# ── Build if needed ───────────────────────────────────────────────────────────

if [[ ! -f "$BINARY" ]]; then
    echo "==> Binary not found — building release binary..."
    cargo build --release
fi

# ── Generate distributed nodes.csv ───────────────────────────────────────────

DIST_CSV="./shared/nodes_distributed.csv"
echo "==> Generating $DIST_CSV (${#MACHINES[@]} machines × $NODES_PER_MACHINE nodes)..."
echo "id,host,port,behavior" > "$DIST_CSV"
node_id=0
for MACHINE in "${MACHINES[@]}"; do
    IP="${MACHINE_IPS[$MACHINE]}"
    for ((p=0; p<NODES_PER_MACHINE; p++)); do
        echo "$node_id,$IP,$((8000+p)),ok" >> "$DIST_CSV"
        ((node_id++))
    done
done
total_nodes=$node_id
echo "    Generated $total_nodes nodes."

# ── Firewall rule ─────────────────────────────────────────────────────────────

echo "==> Creating firewall rule for ports 8000-8004..."
gcloud compute firewall-rules create sparse-bullshark-ports \
    --allow tcp:8000-8004 \
    --source-ranges 10.0.0.0/8 \
    --description "sparse-bullshark inter-node communication" \
    2>/dev/null \
    && echo "    Created." \
    || echo "    Already exists, skipping."

# ── Copy files to each machine (in parallel) ──────────────────────────────────

setup_machine() {
    local MACHINE=$1
    local SSH_FLAGS="-o StrictHostKeyChecking=no -o LogLevel=ERROR"

    echo "==> [$MACHINE] Creating directories..."
    gcloud compute ssh "$MACHINE" --zone "$ZONE" \
        --ssh-flag="$SSH_FLAGS" \
        --command "mkdir -p ~/Sparse_Bullshark/target/release ~/Sparse_Bullshark/shared"

    echo "==> [$MACHINE] Copying binary..."
    gcloud compute scp "$BINARY" \
        "$MACHINE:~/Sparse_Bullshark/target/release/sparse_bullshark" \
        --zone "$ZONE" --ssh-flag="$SSH_FLAGS"

    echo "==> [$MACHINE] Copying config files..."
    # Use the distributed nodes.csv (uploaded as nodes.csv on the remote machine)
    gcloud compute scp "$DIST_CSV" \
        "$MACHINE:~/Sparse_Bullshark/shared/nodes.csv" \
        --zone "$ZONE" --ssh-flag="$SSH_FLAGS"

    gcloud compute scp "./shared/public_keys.toml" \
        "$MACHINE:~/Sparse_Bullshark/shared/public_keys.toml" \
        --zone "$ZONE" --ssh-flag="$SSH_FLAGS"

    gcloud compute scp "./keys" \
        "$MACHINE:~/Sparse_Bullshark/keys" \
        --zone "$ZONE" --ssh-flag="$SSH_FLAGS"

    echo "==> [$MACHINE] Making binary executable..."
    gcloud compute ssh "$MACHINE" --zone "$ZONE" \
        --ssh-flag="$SSH_FLAGS" \
        --command "chmod +x ~/Sparse_Bullshark/target/release/sparse_bullshark"

    echo "==> [$MACHINE] Done."
}

for MACHINE in "${MACHINES[@]}"; do
    setup_machine "$MACHINE" &
done
wait

echo ""
echo "=== Cluster setup complete: $total_nodes nodes across ${#MACHINES[@]} machines ==="
echo ""
echo "Next: python3 run_distributed.py --tx-size 512 --n-tx 500 --mode prbc_sailfish --input-rate 50000"
