#!/bin/bash
echo "=== kernel 评估记录 (最近 8 条) ==="
docker exec asc-asscor-edge0 bash -c "grep 'assessment score computed' /var/log/asscor-kernel.log | grep -oE '\"time\":\"[^\"]+' | tail -8"
echo "=== host1 agent 状态 ==="
docker exec asc-asscor-host1 bash -c "pgrep -x ASSCOR-agent >/dev/null && echo RUNNING || echo DEAD"
echo "=== host1 agent 日志 (最近 5 行) ==="
docker exec asc-asscor-host1 bash -c "tail -5 /var/log/asscor-agent.log"
echo "=== jsonl 当前行数 ==="
docker exec asc-asscor-edge0 bash -c "wc -l /var/lib/asscor/assessments-20260816.jsonl"