#!/bin/bash
echo "=== clean decoyd on all hosts ==="
for c in $(docker ps --format '{{.Names}}' | grep asc-asscor-host); do
  docker exec $c pkill -9 -f decoyd 2>/dev/null
done
sleep 1
echo "=== rerun CR comparison ==="
bash /tmp/exp_cr_compare.sh 2>&1 | grep -E 'round|complete' 
echo ALL-DONE
