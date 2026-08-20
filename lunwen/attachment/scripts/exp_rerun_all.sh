#!/bin/bash
cd /tmp
rm -rf /tmp/exp-results && mkdir -p /tmp/exp-results
# Invalidate old archived data
rm -f /mnt/f/Argus/lunwen/clab-lab/data/experiments/*.jsonl
for exp in E1 E2 E3 E4 E5 E6 E7 E9; do
  echo "=== running $exp (mode C3) ==="
  ./exprunner $exp --json /tmp/exp-results/$exp.jsonl --decoyd /tmp/decoyd --mode C3 2>&1 | grep -E 'round [0-9]+:|complete'
  echo ""
done
echo ALL-DONE
