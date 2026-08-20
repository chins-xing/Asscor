#!/bin/bash
echo "=== 等 OSPF 收敛 ==="
sleep 40
echo "=== 部署 kernel + 12 agents ==="
bash /tmp/deploy_v3_all.sh 2>&1 | tail -20
echo "=== 最终状态 ==="
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep -c accepted" 2>/dev/null
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*' | sort -u | wc -l" 2>/dev/null