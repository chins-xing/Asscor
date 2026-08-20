#!/bin/bash
echo "=== agent processes on host13-18 ==="
for h in 13 14 15 16 17 18; do
  echo -n "host$h: "
  docker exec asc-asscor-host$h pgrep -x ASSCOR-agent >/dev/null 2>&1 && echo RUNNING || echo STOPPED
done
echo "=== host13 agent log ==="
docker exec asc-asscor-host13 tail -8 /var/log/asscor-agent.log 2>&1 | head -10
echo "=== kernel log tail (registration) ==="
docker exec asc-asscor-edge0 tail -12 /var/log/asscor-kernel.log 2>&1 | grep -E 'registered|reject|error' | head -6
echo DONE
