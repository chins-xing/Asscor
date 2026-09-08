#!/bin/bash
echo "=== host2 interfaces ==="
docker exec asc-asscor-host2 ip -br addr 2>&1
echo "=== host2 default route ==="
docker exec asc-asscor-host2 ip route 2>&1 | head -4
echo "=== run decoyd in foreground briefly ==="
docker exec asc-asscor-host2 bash -c 'timeout 2 /tmp/decoyd 22221 2>&1; echo EXIT=$?'
echo "=== host1 can reach host2 eth1? ==="
docker exec asc-asscor-host1 ip route 2>&1 | grep -E '10.10.2|default' | head -3
echo DONE
