#!/bin/bash
sleep 8
echo "=== OSPF Full + 学习到的远端路由 (r1) ==="
docker exec asc-asscor-r1 bash -c "vtysh -c 'show ip route ospf' | grep -E '^O' | grep -v 'directly connected'" 2>&1
echo "=== 跨子网 ping: host1(10.10.1.10) -> host3(10.10.3.10) ==="
docker exec asc-asscor-host1 bash -c "ping -c 3 -W 2 10.10.3.10 2>&1 | tail -3" 2>&1 || echo "(host1 no ping tool)"
echo "=== 跨子网 ping: host2(10.10.2.10) -> host4(10.10.4.10) ==="
docker exec asc-asscor-host2 bash -c "ping -c 3 -W 2 10.10.4.10 2>&1 | tail -3" 2>&1 || echo "(host2 no ping tool)"
echo "=== edge0 -> s5720 真实网络网关 192.168.1.1 ==="
docker exec asc-asscor-edge0 bash -c "ping -c 3 -W 2 192.168.1.1 2>&1 | tail -3" 2>&1 || echo "(edge0 no ping tool)"