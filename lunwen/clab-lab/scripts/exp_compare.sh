#!/bin/bash
cd /tmp
# Comparison groups on the same E2 credential scenario
for mode in C1 C2 C3; do
  echo "=== E2 mode $mode ==="
  ./exprunner E2 --json /tmp/exp-results/E2-$mode.jsonl --decoyd /tmp/decoyd --mode $mode 2>&1 | grep -E 'round [0-9]+:|complete'
done
# Also compare on E1 (recon) C1/C2/C3
for mode in C1 C2 C3; do
  echo "=== E1 mode $mode ==="
  ./exprunner E1 --json /tmp/exp-results/E1-$mode.jsonl --decoyd /tmp/decoyd --mode $mode 2>&1 | grep -E 'round [0-9]+:|complete'
done
echo ALL-DONE
