#!/bin/bash
echo "=== host1 工具与接口 ==="
docker exec asc-asscor-host1 bash -c "which ping ip; ip -br addr show eth1; ip route" 2>&1
echo "=== host1 ping 完整输出 ==="
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.8.10 2>&1
echo "=== host8 侧 ==="
docker exec asc-asscor-host8 bash -c "ip -br addr show eth1; ip route" 2>&1