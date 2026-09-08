#!/bin/bash
cd /tmp
echo "=== comparison CR on host9: C1(no-ACL) C2(static) C3(ACL) ==="
for mode in C1 C2 C3; do
  echo "--- CR mode $mode ---"
  ./exprunner CR --json /tmp/exp-results/CR-$mode.jsonl --decoyd /tmp/decoyd --mode $mode 2>&1 | grep -E 'round [0-9]+:|complete'
done
echo ALL-DONE
