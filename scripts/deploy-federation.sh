#!/usr/bin/env bash
# Deploy a process-isolated federation build (kernel-proc + federation-mod) to
# one master and N node kernels. Replaces the one-off scp/ssh commands used in
# the T4 lab (audit D3).
#
# Usage:
#   scripts/deploy-federation.sh --master user@host --nodes user@n1,user@n2 \
#       [--local-dir build] [--master-dir /opt/asscor/bin] [--node-dir /opt/asscor/bin] \
#       [--service asscor-kernel] [--dry-run]
#
# Expected artifacts (produced by scripts/build.sh):
#   <local-dir>/ASSCOR-kernel-proc-linux-amd64
#   <local-dir>/federation-mod-linux-amd64
set -euo pipefail

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

MASTER=""
NODES=""
LOCAL_DIR="build"
MASTER_DIR="/opt/asscor/bin"
NODE_DIR="/opt/asscor/bin"
SERVICE="asscor-kernel"
DRY_RUN=0
VERIFY=1

while [ $# -gt 0 ]; do
    case "$1" in
        --master) MASTER="${2:-}"; shift 2 ;;
        --nodes) NODES="${2:-}"; shift 2 ;;
        --local-dir) LOCAL_DIR="${2:-}"; shift 2 ;;
        --master-dir) MASTER_DIR="${2:-}"; shift 2 ;;
        --node-dir) NODE_DIR="${2:-}"; shift 2 ;;
        --service) SERVICE="${2:-}"; shift 2 ;;
        --no-verify) VERIFY=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 2 ;;
    esac
done

if [ -z "$MASTER" ] || [ -z "$NODES" ]; then
    echo "error: --master and --nodes are required" >&2
    usage 2
fi

KERNEL="$LOCAL_DIR/ASSCOR-kernel-proc-linux-amd64"
CHILD="$LOCAL_DIR/federation-mod-linux-amd64"
for f in "$KERNEL" "$CHILD"; do
    if [ ! -f "$f" ]; then
        echo "error: missing artifact $f (run scripts/build.sh first)" >&2
        exit 1
    fi
done

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  [dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

deploy_host() {
    local host="$1" dir="$2"
    echo "==> $host ($dir)"
    run scp -q "$KERNEL" "$host:$dir/kernel.new"
    run scp -q "$CHILD" "$host:$dir/federation-mod.new"
    run ssh "$host" "set -e; mv '$dir/kernel.new' '$dir/kernel'; mv '$dir/federation-mod.new' '$dir/federation-mod'; chmod 0755 '$dir/kernel' '$dir/federation-mod'; sudo -n systemctl restart '$SERVICE'"
    if [ "$VERIFY" -eq 1 ]; then
        run ssh "$host" "systemctl is-active '$SERVICE'"
    fi
}

deploy_host "$MASTER" "$MASTER_DIR"
IFS=',' read -r -a node_list <<< "$NODES"
for node in "${node_list[@]}"; do
    node="$(echo "$node" | xargs)"
    [ -n "$node" ] || continue
    deploy_host "$node" "$NODE_DIR"
done

echo "done: master=$MASTER nodes=${#node_list[@]} dry_run=$DRY_RUN"
