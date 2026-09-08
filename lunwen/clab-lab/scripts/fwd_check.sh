#!/bin/bash
echo "=== FRR 容器 ip_forward ==="
for r in r1 r2 r3; do
  echo -n "$r: "; docker exec asc-asscor-$r sysctl -n net.ipv4.ip_forward 2>&1
done
echo "=== host1 路由表 ==="
docker exec asc-asscor-host1 ip route 2>&1