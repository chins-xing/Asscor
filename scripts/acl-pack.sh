#!/bin/bash
# ============================================================
# ACL extension package builder
# Bundles the Attacker Cognitive Loop extension (engine source,
# tools, decoy plugin, experiment assets) into a distributable
# zip under build/.
#
# Usage: bash scripts/acl-pack.sh [output_dir]
#   default output: build/acl-extension-<version>.zip
# ============================================================
set -euo pipefail

VERSION="0.8.0"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/build}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

PKG="$STAGE/acl-$VERSION"
mkdir -p "$PKG"

echo "=== assembling ACL extension package v$VERSION ==="

# 1. engine source (internal)
mkdir -p "$PKG/internal"
for d in attackerstate predictor engagement defensecycle; do
  cp -r "$ROOT/internal/$d" "$PKG/internal/$d"
  rm -f "$PKG/internal/$d"/*_test.go
done

# 2. tools (cmd)
mkdir -p "$PKG/cmd"
for d in exprunner decoyd tracecheck; do
  cp -r "$ROOT/cmd/$d" "$PKG/cmd/$d"
done

# 3. decoy plugin
mkdir -p "$PKG/optional/adversary/packages"
cp -r "$ROOT/optional/adversary/packages/mitre-engage" "$PKG/optional/adversary/packages/mitre-engage"

# 4. extension manifest + docs
cp "$ROOT/optional/adversary/packages/acl/package.json" "$PKG/package.json"
cp "$ROOT/optional/adversary/packages/acl/README.md" "$PKG/README.md"

# 5. experiment assets (topology, configs, scripts, sample data)
mkdir -p "$PKG/experiments"
cp "$ROOT/lunwen/clab-lab/asscor.clab.yml" "$PKG/experiments/" 2>/dev/null || true
cp "$ROOT/lunwen/clab-lab/kernel-config.ini" "$PKG/experiments/" 2>/dev/null || true
cp -r "$ROOT/lunwen/clab-lab/scripts" "$PKG/experiments/scripts" 2>/dev/null || true
if [ -d "$ROOT/lunwen/clab-lab/data/experiments-final" ]; then
  mkdir -p "$PKG/experiments/data"
  cp "$ROOT/lunwen/clab-lab/data/experiments-final/"*.jsonl "$PKG/experiments/data/" 2>/dev/null || true
fi
cp "$ROOT/lunwen/attachment/manual/EXPERIMENT_MANUAL.md" "$PKG/experiments/EXPERIMENT_MANUAL.md" 2>/dev/null || true

# 6. binaries (if present)
if [ -d "$ROOT/build" ]; then
  mkdir -p "$PKG/bin"
  cp "$ROOT/build"/ASSCOR-kernel-v0.2.3-linux-amd64 "$PKG/bin/ASSCOR-kernel" 2>/dev/null || true
  cp "$ROOT/build"/ASSCOR-agent-v0.2.3-linux-amd64 "$PKG/bin/ASSCOR-agent" 2>/dev/null || true
  cp "$ROOT/build"/exprunner-linux-amd64 "$PKG/bin/exprunner" 2>/dev/null || true
  cp "$ROOT/build"/decoyd-linux-amd64 "$PKG/bin/decoyd" 2>/dev/null || true
fi

# 7. zip it
mkdir -p "$OUT_DIR"
ZIP="$OUT_DIR/acl-$VERSION.zip"
rm -f "$ZIP"
(cd "$STAGE" && zip -qr "$ZIP" "acl-$VERSION")
echo "=== built: $ZIP ==="
echo "contents:"
unzip -l "$ZIP" | tail -5
