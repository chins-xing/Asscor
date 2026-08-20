#!/bin/bash
echo "=== edge0 数据目录 ==="
docker exec asc-asscor-edge0 ls -la /var/lib/asscor/*.jsonl 2>&1 | tail -5
echo "=== 当前日期 ==="
date -u
docker exec asc-asscor-edge0 date -u
echo "=== host1 agent 状态 ==="
docker exec asc-asscor-host1 bash -c "pgrep -x ASSCOR-agent >/dev/null && echo RUNNING || echo DEAD; tail -3 /var/log/asscor-agent.log 2>/dev/null | tail -2"