#!/bin/bash
cd /tmp
mkdir -p /tmp/exp-results
for exp in E1 E2 E3 E4 E5 E6; do
  echo "=== running $exp ==="
  ./exprunner $exp --json /tmp/exp-results/$exp.jsonl --decoyd /tmp/decoyd 2>&1 | grep -E 'round [0-9]|complete'
  echo ""
done
echo ALL-DONE
