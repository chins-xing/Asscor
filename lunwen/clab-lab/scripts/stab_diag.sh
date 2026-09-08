#!/bin/bash
echo "=== monitor.out ==="
cat /tmp/stability-monitor.out 2>/dev/null || echo "(no out)"
echo "=== 进程 ==="
ps aux | grep -E "stab_monitor|stability" | grep -v grep
echo "=== stability 目录 ==="
ls -la /tmp/stability/ 2>/dev/null || echo "(no dir)"