#!/bin/bash
# Clean all decoyd processes across all containers before comparison runs
echo "=== killing decoyd on all containers ==="
for c in $(docker ps --format '{{.Names}}' | grep asc-asscor-host); do
  docker exec $c pkill -f decoyd 2>/dev/null && echo "killed on $c" || true
done
sleep 2
echo "=== verify none listening ==="
for c in asc-asscor-host2 asc-asscor-host13 asc-asscor-host14; do
  echo -n "$c: "
  docker exec $c pgrep -f decoyd >/dev/null 2>&1 && echo STILL-RUNNING || echo CLEAN
done
echo DONE
