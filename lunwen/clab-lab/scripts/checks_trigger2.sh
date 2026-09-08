#!/bin/bash
echo "=== 缩短 host1 检查间隔到 30s ==="
docker exec asc-asscor-host1 bash -c "sed -i 's/check_interval_sec = 300/check_interval_sec = 30/' /etc/asscor/agent.ini"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
echo "等待注册+同步+下一轮检查 (90s)..."
sleep 90
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "=== CU- 结果 ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-[0-9]+","domain":"[^"]*","name":"[^"]*","passed":(true|false),"delta":[-0-9]+,"detail":"[^"]{0,80}' | head -8
echo "=== check_count ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_count":[0-9]+'