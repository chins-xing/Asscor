#!/bin/bash
sleep 20
echo "=== r2 到 host8 子网的多路径路由 ==="
docker exec asc-asscor-r2 vtysh -c "show ip route 10.10.8.0/24" 2>/dev/null | grep -E "10.10.8.0|via"
echo "=== r3 到 host1 子网 (应有多条 via) ==="
docker exec asc-asscor-r3 vtysh -c "show ip route 10.10.1.0/24" 2>/dev/null | grep "via"
echo "=== 环路稳定性: host1 -> host8 (跨环) ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.8.10 2>&1 | tail -1
echo "=== host1 -> host12 (另一环方向) ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.12.10 2>&1 | tail -1
echo "=== host12 -> s5720 真实网络 ==="
docker exec asc-asscor-host12 ping -c 2 -W 2 192.168.1.1 2>&1 | tail -1
echo "=== r2 完整路由数 ==="
docker exec asc-asscor-r2 vtysh -c "show ip route" 2>/dev/null | grep -c "via"