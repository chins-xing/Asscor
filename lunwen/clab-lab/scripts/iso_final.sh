#!/bin/bash
echo "=== E12 补验: host1 绑定 ==="
docker exec asc-asscor-edge0 bash -c "grep -o '\"host1\":\"[a-f0-9]\{8\}' /var/lib/asscor/heartbeat_identity.json || echo 'host1 未绑定?!'"
docker exec asc-asscor-edge0 bash -c "grep '\"host_id\":\"host1\"' /var/log/asscor-kernel.log | grep 'registered' | tail -1 | grep -oE 'action[^,]*|result[^,]*'"
echo "=== E15 统计 ==="
echo "-- 评估轮次总数 --"
docker exec asc-asscor-edge0 bash -c "grep -c '\"final_score\"' /var/lib/asscor/assessments-20260816.jsonl 2>/dev/null || wc -l < /var/lib/asscor/assessments-20260816.jsonl"
echo "-- panic 数 --"
docker exec asc-asscor-edge0 bash -c "grep -c 'panic' /var/log/asscor-kernel.log"
echo "-- 12 台最近评估分数分布 --"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
grep -oE '\"host_id\":\"host[0-9]+\",\"hostname\":\"host[0-9]+\",\"final_score\":[0-9.]+' /tmp/assessments.jsonl | tail -12 | sed 's/.*final_score\"://' | sort | uniq -c