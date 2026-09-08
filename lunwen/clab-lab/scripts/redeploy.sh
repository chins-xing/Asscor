#!/bin/bash
cd ~/clab/asscor
echo "=== destroy + deploy 全新验证 ==="
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -3
sleep 3
sudo containerlab deploy -t asscor.clab.yml 2>&1 | grep -E "INFO|WARN|ERROR" | tail -8
echo "=== 等待 exec + FRR 收敛 ==="
sleep 20
echo "=== 综合验证 ==="
echo "-- 内部跨子网 host1->host3 --"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.3.10 2>&1 | tail -1
echo "-- 出真实网络 host3->s5720 --"
docker exec asc-asscor-host3 ping -c 2 -W 2 192.168.1.1 2>&1 | tail -1
echo "-- edge0->s5720 --"
docker exec asc-asscor-edge0 ping -c 2 -W 2 192.168.1.1 2>&1 | tail -1
echo "-- OSPF 默认路由 (r2) --"
docker exec asc-asscor-r2 vtysh -c "show ip route" 2>/dev/null | grep -E "0.0.0.0/0|10.10.3.0/24"