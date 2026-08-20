#!/bin/bash
echo "=== host1 -> 10.10.8.10 (重测) ==="
docker exec asc-asscor-host1 ping -c 5 -W 2 10.10.8.10 2>&1 | tail -2
echo "=== host1 -> 10.10.5.10 (r4 下) ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.5.10 2>&1 | tail -1
echo "=== host8 -> host1 (反向) ==="
docker exec asc-asscor-host8 ping -c 3 -W 2 10.10.1.10 2>&1 | tail -1
echo "=== host1 直接 ping r1 eth1 (10.10.0.1) ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.0.1 2>&1 | tail -1
echo "=== host1 ping r5 (10.10.200.14) ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.200.14 2>&1 | tail -1