#!/bin/bash
sleep 60
echo "=== 监控运行状态 ==="
ps aux | grep stab_monitor | grep -v grep | head -1 | awk '{print "pid="$2, "start="$9}'
echo "=== 首个采样 ==="
cat /tmp/stability/stability.csv
echo "=== 环境健康 ==="
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo KERNEL-UP || echo KERNEL-DOWN; grep -c 'identity: agent registered' /var/log/asscor-kernel.log"
echo "=== 保持进程 ==="
pgrep -f 'sleep infinity' >/dev/null && echo "WSL keepalive RUNNING" || echo "keepalive MISSING"