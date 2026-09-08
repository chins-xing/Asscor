#!/bin/bash
echo "=== 1. 停监控进程 ==="
kill $(cat /tmp/stability/monitor.pid 2>/dev/null) 2>/dev/null && echo "monitor killed" || echo "monitor pid not found"
pkill -f stab_monitor.sh 2>/dev/null; sleep 1
ps aux | grep stab_monitor | grep -v grep | wc -l
echo "=== 2. 清理测试环境 ==="
cd ~/clab/asscor
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -1
echo "=== 3. 清理临时文件 ==="
rm -rf /tmp/stability /tmp/stab_monitor.sh /tmp/stab_*.sh /tmp/ASSCOR-* /tmp/kernel-config.ini /tmp/deploy_v3_all.sh 2>/dev/null
docker ps -a --filter name=asc-asscor --format "{{.Names}}" | wc -l
echo "cleaned"