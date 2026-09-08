#!/bin/bash
echo "=== host1 -> host9 ping ==="
docker exec asc-asscor-host1 ping -c 2 -W 3 10.10.9.10 2>&1 | tail -1
echo "=== host9 default gw ==="
docker exec asc-asscor-host9 ip route 2>&1 | head -3
echo "=== r2 has 10.10.9.1? ==="
docker exec asc-asscor-r2 ip -br addr 2>&1 | grep '10.10.9'
echo "=== r1 route to 10.10.9.0/24 ==="
docker exec asc-asscor-r1 vtysh -c 'show ip route 10.10.9.0/24' 2>/dev/null | head -3
echo "=== host9 can reach kernel? ==="
docker exec asc-asscor-host9 ping -c 2 -W 3 10.10.0.10 2>&1 | tail -1
echo DONE
