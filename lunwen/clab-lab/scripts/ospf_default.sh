#!/bin/bash
echo "=== r1 宣告默认路由 ==="
docker exec asc-asscor-r1 vtysh -c "configure terminal" -c "router ospf" -c "default-information originate" 2>&1 | grep -v vtysh.conf
sleep 6
echo "=== r2/r3 是否学到默认路由 ==="
docker exec asc-asscor-r2 vtysh -c "show ip route" 2>&1 | grep -v vtysh.conf | grep "0.0.0.0/0"
docker exec asc-asscor-r3 vtysh -c "show ip route" 2>&1 | grep -v vtysh.conf | grep "0.0.0.0/0"
echo "=== host3 -> s5720 (经 r1 NAT) ==="
docker exec asc-asscor-host3 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2
echo "=== host2 -> s5720 ==="
docker exec asc-asscor-host2 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2