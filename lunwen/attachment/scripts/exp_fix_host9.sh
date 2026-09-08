#!/bin/bash
echo "=== host9 interfaces ==="
docker exec asc-asscor-host9 ip -br addr 2>&1 | grep -E 'eth|lo'
echo "=== host9 /sys/class/net ==="
docker exec asc-asscor-host9 ls /sys/class/net/ 2>&1
echo "=== host13 (works) interfaces ==="
docker exec asc-asscor-host13 ip -br addr 2>&1 | grep eth1
echo "=== manually add host9 eth1 config ==="
docker exec asc-asscor-host9 bash -c "ip addr add 10.10.9.10/24 dev eth1 2>/dev/null; ip route replace default via 10.10.9.1 dev eth1 2>/dev/null; ip -br addr | grep eth1"
echo DONE
