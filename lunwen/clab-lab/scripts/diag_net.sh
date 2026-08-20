#!/bin/bash
echo "=== kernel 存活/监听 ==="
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo KERNEL-RUNNING; ss -tln | grep -c 50051"
echo "=== host1 ping kernel (10.10.0.10) ==="
docker exec asc-asscor-host1 ping -c 2 -W 3 10.10.0.10 2>&1 | tail -1
echo "=== host1 路由表 ==="
docker exec asc-asscor-host1 ip route 2>&1
echo "=== host1 接口 ==="
docker exec asc-asscor-host1 ip -br addr 2>&1 | head -4
echo "=== host2 ping kernel ==="
docker exec asc-asscor-host2 ping -c 2 -W 3 10.10.0.10 2>&1 | tail -1
echo "=== r2 iptables (残留规则?) ==="
docker exec asc-asscor-r2 iptables -L FORWARD -n 2>&1 | head -6