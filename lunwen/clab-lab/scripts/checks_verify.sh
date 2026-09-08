#!/bin/bash
echo "=== 1. kernel config.ini user_check 段现状 ==="
docker exec asc-asscor-edge0 bash -c "grep -A2 '\[user_check' /etc/asscor/config.ini | head -20"
echo "=== 2. 重启 kernel + agent 干净重验 ==="
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 30
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 90
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "=== 3. 最新评估的 CU 检查项 ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-[0-9]+","domain":"[^"]*","name":"[^"]*","passed":(true|false),"detail":"[^"]{0,50}' | head -8
echo "=== 4. check_count ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_count":[0-9]+'
echo "=== 5. host1 agent 同步日志 (user_checks 数) ==="
docker exec asc-asscor-host1 bash -c "grep 'applied synced' /var/log/asscor-agent.log | tail -2"