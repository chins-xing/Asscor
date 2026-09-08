#!/bin/bash
echo "===== E12: 删除 A(host1) 后重新创建 ====="
echo "-- 删除前绑定 --"
docker exec asc-asscor-edge0 bash -c "cat /var/lib/asscor/heartbeat_identity.json | grep -o '\"host1\":\"[a-f0-9]\{8\}'"
echo "-- 删除 host1 绑定 (编辑 identity.json) --"
docker exec asc-asscor-edge0 bash -c "sed -i 's/\"host1\":\"[a-f0-9]*\",\?//' /var/lib/asscor/heartbeat_identity.json && cat /var/lib/asscor/heartbeat_identity.json | grep -c host1 || echo 'host1 已删除'"
echo "-- 重启 kernel (E12+E14 共同触发点) --"
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 60
echo "-- E12: host1 重新注册 (应作为首次绑定重新绑定) --"
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep host1 | tail -1"
echo "-- E12: 重新绑定后 identity 恢复 --"
docker exec asc-asscor-edge0 bash -c "grep -o '\"host1\":\"[a-f0-9]\{8\}' /var/lib/asscor/heartbeat_identity.json"
echo "-- E14: engine 重启后 12 agent 重连评估数 --"
docker exec asc-asscor-edge0 bash -c "grep -c 'identity: agent registered' /var/log/asscor-kernel.log; grep -c 'assessment score computed' /var/log/asscor-kernel.log"
echo "-- E14: 各主机评估独立 (分数分布) --"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
grep -oE '"host_id":"[a-z0-9]+","hostname":"[a-z0-9]+","final_score":[0-9.]+' /tmp/assessments.jsonl | tail -12

echo ""
echo "===== E13: Agent 重启后重新评估 ====="
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 55
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host1 重启前后评估对比 (分数应一致) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -2 | grep -oE '"final_score":[0-9.]+'
echo "-- host2 未被影响 (最后评估时间戳) --"
grep '"host_id":"host2"' /tmp/assessments.jsonl | tail -1 | grep -oE '"timestamp":"[^"]*"' | head -1