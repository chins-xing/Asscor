#!/bin/bash
echo "=== r1 OSPF 邻居 ==="
docker exec asc-asscor-r1 vtysh -c "show ip ospf neighbor" 2>&1 | grep -v vtysh.conf
echo "=== r1 完整路由 ==="
docker exec asc-asscor-r1 vtysh -c "show ip route" 2>&1 | grep -v vtysh.conf | head -20
echo "=== r2 完整路由 ==="
docker exec asc-asscor-r2 vtysh -c "show ip route" 2>&1 | grep -v vtysh.conf | head -20
echo "=== r2 OSPF 邻居 ==="
docker exec asc-asscor-r2 vtysh -c "show ip ospf neighbor" 2>&1 | grep -v vtysh.conf