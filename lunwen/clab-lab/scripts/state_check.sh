#!/bin/bash
echo "=== 当前状态 ==="
echo "-- r1 容器 --"; docker ps --filter name=asc-asscor-r1 --format "{{.Names}} {{.Status}}"
echo "-- host1 agent --"; docker exec asc-asscor-host1 bash -c "pgrep -x ASSCOR-agent >/dev/null && echo RUNNING || echo DEAD" 2>/dev/null
echo "-- host5 agent --"; docker exec asc-asscor-host5 bash -c "pgrep -x ASSCOR-agent >/dev/null && echo RUNNING || echo DEAD" 2>/dev/null
echo "-- kernel 最近心跳 --"; docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | tail -1" 2>/dev/null