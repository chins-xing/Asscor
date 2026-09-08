#!/bin/bash
sleep 25
echo "=== 心跳统计 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'heartbeat received' /var/log/asscor-kernel.log"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*' | sort | uniq -c"
echo "=== host1 心跳日志 ==="
docker exec asc-asscor-host1 bash -c "grep -iE 'heartbeat|cycle' /var/log/asscor-agent.log | tail -3"
echo "=== kernel 最新日志 (错误?) ==="
docker exec asc-asscor-edge0 bash -c "grep -iE 'error|reject|warn' /var/log/asscor-kernel.log | tail -3"