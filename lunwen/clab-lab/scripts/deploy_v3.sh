#!/bin/bash
cd ~/clab/asscor
echo "=== destroy 旧拓扑 ==="
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -1
sleep 3
echo "=== deploy v3 ==="
sudo containerlab deploy -t asscor.clab.yml 2>&1 | grep -cE "INFO .*running"
sudo containerlab inspect -t asscor.clab.yml 2>/dev/null | grep -c "running"
echo "=== 等收敛 ==="
sleep 30
echo "=== r1 OSPF 邻居 ==="
docker exec asc-asscor-r1 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -cE "Full|2-Way"
echo "=== 多路径检查: r2 到 host8 (10.10.8.0/24) 的路由 ==="
docker exec asc-asscor-r2 vtysh -c "show ip route 10.10.8.0/24" 2>/dev/null | grep -E "10.10.8.0" | head -5
echo "=== 环路稳定性: host1 -> host8 ping ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.8.10 2>&1 | tail -1
echo "=== host12 -> s5720 ==="
docker exec asc-asscor-host12 ping -c 2 -W 2 192.168.1.1 2>&1 | tail -1