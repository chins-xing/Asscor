#!/bin/bash
echo "=== kernel 日志: 注册记录 ==="
docker exec asc-asscor-edge0 bash -c "grep -E 'identity: agent registered' /var/log/asscor-kernel.log | tail -6"
echo "=== identity 绑定文件 ==="
docker exec asc-asscor-edge0 bash -c "cat /var/lib/asscor/heartbeat_identity.json 2>/dev/null; echo"
echo "=== 心跳 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'heartbeat received' /var/log/asscor-kernel.log"
echo "=== 各 agent 日志尾部 ==="
for i in 1 2 3 4; do
  echo "-- host$i --"
  docker exec asc-asscor-host$i bash -c "tail -3 /var/log/asscor-agent.log 2>/dev/null | grep -E 'register|error|ERROR|heartbeat' | tail -2"
done