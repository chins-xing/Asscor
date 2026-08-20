#!/bin/bash
echo "=== 监控进程 ==="
ps aux | grep -E "stab_monitor|sleep infinity" | grep -v grep | awk '{print $2, $11, $12, $13}'
echo "=== 环境状态 ==="
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo KERNEL-UP"
docker ps --filter name=asc-asscor --format "{{.Names}}" | wc -l
echo "=== 监控输出目录 ==="
ls -la /tmp/stability/
echo "=== 预计完成时间 ==="
date -u -d "+168 hours" +"%Y-%m-%dT%H:%M:%SZ (UTC)"