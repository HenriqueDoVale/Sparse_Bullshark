#!/usr/bin/env bash
# setup_keys.sh — export PRIVATE_KEY_X environment variables into the current shell.
#
# IMPORTANT: this script must be SOURCED, not executed directly.
#   Correct:   source setup_keys.sh --nodes 8
#   Correct:   . setup_keys.sh --nodes 8
#   Wrong:     ./setup_keys.sh --nodes 8   (vars won't persist in your shell)
#
# Usage:
#   source setup_keys.sh --nodes N    set keys for nodes 0..N-1
#   source setup_keys.sh              set keys for all entries in the keys file

KEYS_FILE="./keys"
N_NODES=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --nodes|-n)
            N_NODES="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: source setup_keys.sh [--nodes N]"
            return 1 2>/dev/null || exit 1
            ;;
    esac
done

if [[ ! -f "$KEYS_FILE" ]]; then
    echo "Error: keys file not found at $KEYS_FILE"
    echo "Run this script from the project root directory."
    return 1 2>/dev/null || exit 1
fi

node_id=0
while IFS=: read -r private_key _rest; do
    [[ -z "$private_key" ]] && continue
    if [[ $N_NODES -gt 0 && $node_id -ge $N_NODES ]]; then
        break
    fi
    export "PRIVATE_KEY_${node_id}=${private_key}"
    node_id=$((node_id + 1))
done < "$KEYS_FILE"

echo "Exported $node_id private key(s) (PRIVATE_KEY_0 .. PRIVATE_KEY_$((node_id - 1)))."
