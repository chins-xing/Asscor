#!/bin/bash
echo "=== host2 decoyd process ==="
docker exec asc-asscor-host2 ps aux 2>/dev/null | grep -i decoyd | grep -v grep || echo "none"
echo "=== host13 decoyd process ==="
docker exec asc-asscor-host13 ps aux 2>/dev/null | grep -i decoyd | grep -v grep || echo "none"
echo "=== force kill with pid ==="
for c in asc-asscor-host2 asc-asscor-host13 asc-asscor-host14; do
  PID=$(docker exec $c pgrep -f decoyd 2>/dev/null | head -1)
  if [ -n "$PID" ]; then
    docker exec $c kill -9 $PID 2>/dev/null && echo "killed $PID on $c"
  fi
done
sleep 1
echo "=== re-verify ==="
for c in asc-asscor-host2 asc-asscor-host13 asc-asscor-host14; do
  echo -n "$c: "
  docker exec $c pgrep -f decoyd >/dev/null 2>&1 && echo STILL-RUNNING || echo CLEAN
done
echo DONE
