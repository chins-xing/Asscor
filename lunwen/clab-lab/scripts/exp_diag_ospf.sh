#!/bin/bash
echo "=== r1 OSPF routes for new subnets ==="
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' 2>/dev/null | grep -E '10.10.1[3-8]' || echo "NO-ROUTES-FOR-13-18"
echo "=== r1 total OSPF routes ==="
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' 2>/dev/null | grep -c 'O>*'
echo "=== r2 OSPF neighbors ==="
docker exec asc-asscor-r2 vtysh -c 'show ip ospf neighbor' 2>/dev/null | grep -E 'Neighbor|2-Way|Full' | head -6
echo "=== r2 redistribute check (config) ==="
docker exec asc-asscor-r2 cat /etc/frr/frr.conf 2>/dev/null | head -15
echo DONE
