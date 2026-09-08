#!/bin/bash
cd ~/clab/asscor
echo "=== destroy 旧拓扑 ==="
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -2
sleep 3
echo "=== deploy 扩容拓扑 ==="
sudo containerlab deploy -t asscor.clab.yml 2>&1 | grep -cE "INFO .*running" 
sudo containerlab inspect -t asscor.clab.yml 2>/dev/null | grep -c "running"
echo "=== 等 exec + OSPF 收敛 ==="
sleep 25
echo "=== 验证: 跨 4 跳路由 host1->host8 ==="
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.8.10 2>&1 | tail -1
echo "=== 验证: host5->host7 ==="
docker exec asc-asscor-host5 ping -c 2 -W 2 10.10.7.10 2>&1 | tail -1
echo "=== 验证: host8->s5720 真实网络 ==="
docker exec asc-asscor-host8 ping -c 2 -W 2 192.168.1.1 2>&1 | tail -1
echo "=== r1 OSPF 邻居数 (期望 4) ==="
docker exec asc-asscor-r1 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -cE "Full|2-Way"