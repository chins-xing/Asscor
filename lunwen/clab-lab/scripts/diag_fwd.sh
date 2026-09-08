#!/bin/bash
echo "=== ip_forward ==="
for r in r2 r5; do echo -n "$r: "; docker exec asc-asscor-$r sysctl -n net.ipv4.ip_forward; done
echo "=== r2 ping host8 (转发路径) ==="
docker exec asc-asscor-r2 ping -c 2 -W 2 10.10.8.10 2>&1 | tail -1
echo "=== r5 ping host1 (反向路径) ==="
docker exec asc-asscor-r5 ping -c 2 -W 2 10.10.1.10 2>&1 | tail -1
echo "=== host1 ping 网关 r2 eth2 (10.10.1.1) ==="
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.1.1 2>&1 | tail -1
echo "=== host1 ARP ==="
docker exec asc-asscor-host1 bash -c "ip neigh show dev eth1" 2>&1