#!/bin/bash
echo "=== 重启 host1 agent (同步后触发含 user_check 评估) ==="
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 65
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "=== CU- 结果 ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-[0-9]+","domain":"[^"]*","name":"[^"]*","passed":(true|false),"delta":[-0-9]+,"detail":"[^"]{0,80}' | head -8
echo "=== 检查项总数 (host1 最新) ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_count":[0-9]+'