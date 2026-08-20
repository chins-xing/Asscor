#!/bin/bash
echo "############ Assessment 正确性实验 ############"
echo "=== E1 确定性: host1 环境不变, 连续 3 次评估 ==="
for round in 1 2 3; do
  docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
  sleep 55
done
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "--- host1 最近 3 次评估 (环境: 无 sshd_config) ---"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -3 | grep -oE '"timestamp":"[^"]*"|"final_score":[0-9.]+|"attack_surface":[0-9]+|"operation_trust":[0-9]+|"prism_score":[0-9.]+' | paste - - - - -
echo ""
echo "=== E2 单检查项隔离: AS-003 翻转 (好->坏->好) ==="
echo "-- 1. host1 装良好 sshd_config --"
docker exec asc-asscor-host1 bash -c "mkdir -p /etc/ssh && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 55
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host1 良好配置评估 (预期 AS-003 pass, AS=68, 总分≈59.09) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"attack_surface":[0-9]+|"business_continuity":[0-9]+|"operation_trust":[0-9]+|"resilience":[0-9]+|"kernel_security":[0-9]+|"prism_score":[0-9.]+'
echo "-- 2. host1 改坏 sshd_config --"
docker exec asc-asscor-host1 bash -c "printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n' > /etc/ssh/sshd_config"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 55
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host1 坏配置评估 (预期 AS-003 fail, AS=58, 总分≈58.27) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"attack_surface":[0-9]+|"business_continuity":[0-9]+|"operation_trust":[0-9]+|"resilience":[0-9]+|"kernel_security":[0-9]+|"prism_score":[0-9.]+'
echo "-- 3. host1 恢复良好 --"
docker exec asc-asscor-host1 bash -c "printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 55
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host1 恢复良好评估 (预期回到≈59.09) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"attack_surface":[0-9]+|"prism_score":[0-9.]+'
echo "done"