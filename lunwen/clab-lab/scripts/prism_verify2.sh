#!/bin/bash
F=/var/lib/asscor/assessments-$(date -u +%Y%m%d).jsonl
echo "=== 现有 host1 评估 (第 1 轮基线) ==="
docker cp asc-asscor-edge0:$F /tmp/assessments.jsonl
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"prism_score":[0-9.]+|"debt_raw":[0-9.]+|"debt_penalty":[0-9.]+|"fail_at":[0-9]+' | paste - - - - - 
echo "=== 60s 后触发第 2 轮 ==="
sleep 60
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 65
docker cp asc-asscor-edge0:$F /tmp/assessments.jsonl
echo "--- 第 2 轮 ---"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"prism_score":[0-9.]+|"debt_raw":[0-9.]+|"debt_penalty":[0-9.]+|"fail_at":[0-9]+' | paste - - - - - 
echo "=== 120s 后第 3 轮 ==="
sleep 120
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 65
docker cp asc-asscor-edge0:$F /tmp/assessments.jsonl
echo "--- 第 3 轮 ---"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"prism_score":[0-9.]+|"debt_raw":[0-9.]+|"debt_penalty":[0-9.]+|"fail_at":[0-9]+' | paste - - - - - 