#!/bin/bash
echo "=== 脚本大小 ==="
wc -c /tmp/stab_monitor.sh
echo "=== setsid 启动 ==="
setsid bash /tmp/stab_monitor.sh </dev/null >/tmp/stability-monitor.out 2>&1 &
disown
sleep 5
echo "=== 进程与首个采样 ==="
ps aux | grep stab_monitor | grep -v grep | head -1
cat /tmp/stability/stability.csv 2>/dev/null