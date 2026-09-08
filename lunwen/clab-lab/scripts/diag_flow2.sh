#!/bin/bash
echo "=== kernel 日志统计 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'identity: agent registered' /var/log/asscor-kernel.log; grep -c 'heartbeat received' /var/log/asscor-kernel.log; grep -c 'processing check results' /var/log/asscor-kernel.log"
echo "=== 最近日志 8 条 ==="
docker exec asc-asscor-edge0 bash -c "tail -8 /var/log/asscor-kernel.log"
echo "=== agent 状态 ==="
docker exec asc-asscor-host1 bash -c "tail -3 /var/log/asscor-agent.log"