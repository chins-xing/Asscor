#!/bin/bash
echo "=== host1 接口与路由 ==="
docker exec asc-asscor-host1 bash -c "ip -br addr show; echo ---; ip route" 2>&1
echo "=== edge0 接口与路由 ==="
docker exec asc-asscor-edge0 bash -c "ip -br addr show; echo ---; ip route" 2>&1
echo "=== r2 接口 (zebra 是否应用 IP) ==="
docker exec asc-asscor-r2 bash -c "ip -br addr show eth1 eth2 eth3" 2>&1