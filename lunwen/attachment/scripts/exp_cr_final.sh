#!/bin/bash
echo "=== precise decoyd cleanup (not matching exprunner) ==="
for c in $(docker ps --format '{{.Names}}' | grep asc-asscor-host); do
  # match only the decoyd binary process, not exprunner's --decoyd arg
  docker exec $c bash -c "pkill -9 -x decoyd 2>/dev/null" 2>/dev/null
done
sleep 1
echo "cleaned"
echo "=== run CR comparison ==="
cd /tmp
for mode in C1 C2 C3; do
  echo "--- CR mode $mode ---"
  ./exprunner CR --json /tmp/exp-results/CR-$mode.jsonl --decoyd /tmp/decoyd --mode $mode 2>&1 | grep -E 'round [0-9]+:|complete'
done
echo ALL-DONE
