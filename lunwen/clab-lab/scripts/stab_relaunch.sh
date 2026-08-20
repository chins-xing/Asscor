#!/bin/bash
echo "=== 脚本前 10 行 (检查 \$ 是否完整) ==="
head -12 /tmp/stab_monitor.sh
echo "=== setsid 启动 ==="
setsid bash /tmp/stab_monitor.sh </dev/null >/tmp/stability-monitor.out 2>&1 &
disown
echo "launched"
sleep 3
echo "=== 立即检查 ==="
ps aux | grep stab_monitor | grep -v grep | head -1