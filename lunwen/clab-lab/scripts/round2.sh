#!/bin/bash
echo "=== 重启 8 agent 触发新一轮评估 ==="
for i in $(seq 1 8); do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
echo "restarted, waiting for assessment round..."
sleep 70
echo "=== 新评估轮次统计 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'assessment score computed' /var/log/asscor-kernel.log"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "=== 最近一轮各主机 (含传播边) ==="
grep -c "host" /tmp/assessments.jsonl