#!/bin/bash
cd ~/clab/asscor
echo "=== 1. destroy + deploy 重建 ==="
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -1
sleep 5
sudo containerlab deploy -t asscor.clab.yml 2>&1 | grep -cE "INFO .*running"
sleep 30
echo "=== 2. 验证网络 ==="
docker exec asc-asscor-edge0 bash -c "ip -br addr show eth1 2>/dev/null | head -1"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.0.10 2>&1 | tail -1
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.8.10 2>&1 | tail -1