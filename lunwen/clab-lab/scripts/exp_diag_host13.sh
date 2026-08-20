#!/bin/bash
echo "=== host13 routes ==="
docker exec asc-asscor-host13 ip route 2>&1 | head -4
echo "=== host13 -> kernel 10.10.0.10 ==="
docker exec asc-asscor-host13 ping -c 2 -W 3 10.10.0.10 2>&1 | tail -1
echo "=== host13 -> r2 eth7 gw 10.10.13.1 ==="
docker exec asc-asscor-host13 ping -c 2 -W 3 10.10.13.1 2>&1 | tail -1
echo "=== r2 has 10.10.13.1? ==="
docker exec asc-asscor-r2 ip -br addr 2>&1 | grep -E 'eth7|eth8|10.10.13|10.10.14'
echo DONE
