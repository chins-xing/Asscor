#!/bin/bash
echo "=== FRR 进程 ==="
for r in r1 r2 r3; do
  echo "--- $r ---"
  docker exec asc-asscor-$r bash -c "ps aux | grep -E 'zebra|ospfd' | grep -v grep | awk '{print \$11}' | sort -u" 2>&1
  cat /tmp/frr-init.log 2>/dev/null | tail -2
done
echo "=== OSPF 邻居 (r1) ==="
docker exec asc-asscor-r1 bash -c "vtysh -c 'show ip ospf neighbor' 2>/dev/null || echo vtysh-unavailable" 2>&1 | head -10
echo "=== r1 路由表 ==="
docker exec asc-asscor-r1 bash -c "vtysh -c 'show ip route ospf' 2>/dev/null | head -12" 2>&1