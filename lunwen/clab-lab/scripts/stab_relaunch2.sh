#!/bin/bash
echo "=== 停旧监控 ==="
kill $(cat /tmp/stability/monitor.pid 2>/dev/null) 2>/dev/null; sleep 1
pkill -f stab_monitor.sh 2>/dev/null; sleep 1
rm -rf /tmp/stability
echo "=== 启动新监控 ==="
setsid bash /tmp/stab_monitor.sh </dev/null >/tmp/stability-monitor.out 2>&1 &
disown
sleep 6
echo "=== 进程 ==="
ps aux | grep stab_monitor | grep -v grep | head -1 | awk '{print "pid="$2}'
echo "=== 首个采样 (应单行 CSV) ==="
cat /tmp/stability/stability.csv
echo "=== 行数检查 ==="
wc -l < /tmp/stability/stability.csv