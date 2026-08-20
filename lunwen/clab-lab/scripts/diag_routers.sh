#!/bin/bash
echo "=== r2 OSPF 邻居与远端路由 ==="
docker exec asc-asscor-r2 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -E "Neighbor|Full|2-Way"
docker exec asc-asscor-r2 vtysh -c "show ip route" 2>/dev/null | grep -E "10.10.8.0|10.10.0.0"
echo "=== r5 OSPF 邻居与路由 ==="
docker exec asc-asscor-r5 vtysh -c "show ip ospf neighbor" 2>/dev/null | grep -E "Neighbor|Full|2-Way"
docker exec asc-asscor-r5 vtysh -c "show ip route" 2>/dev/null | grep -E "10.10.1.0|10.10.0.0"
echo "=== r2 ping r1 (链路) ==="
docker exec asc-asscor-r2 ping -c 2 -W 2 10.10.200.1 2>&1 | tail -1