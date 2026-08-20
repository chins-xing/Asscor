#!/bin/bash
echo "############ 故障注入 E29-E39 ############"
echo ""
echo "===== E29: Agent kill ====="
docker exec asc-asscor-host1 bash -c "kill -9 \$(pgrep -x ASSCOR-agent)"
echo "agent killed, 等待 75s (心跳超时)..."
sleep 75
echo "-- kernel 超时检测 --"
docker exec asc-asscor-edge0 bash -c "grep 'agent timed out' /var/log/asscor-kernel.log | grep host1 | tail -1"
echo "-- 重启 agent --"
docker exec asc-asscor-host1 bash -c "nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 45
echo "-- 恢复: 重新注册 + 心跳 --"
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'result[^,]*'"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'has_result[^,]*'"
echo "-- E37/38: 恢复后重新评估 --"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+'

echo ""
echo "===== E30: Engine kill ====="
docker exec asc-asscor-edge0 bash -c "kill -9 \$(pgrep -x ASSCOR-kernel)"
echo "kernel killed, 等待 40s (agent 断连重试)..."
sleep 40
echo "-- agent 侧断连日志 --"
docker exec asc-asscor-host2 bash -c "tail -5 /var/log/asscor-agent.log | grep -iE 'cycle|retry|unreachable' | tail -2"
echo "-- 重启 kernel --"
docker exec asc-asscor-edge0 bash -c "cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 60
echo "-- 恢复: 身份绑定持久化 + agent 重连 --"
docker exec asc-asscor-edge0 bash -c "grep -o '\"host1\":\"[a-f0-9]\{8\}' /var/lib/asscor/heartbeat_identity.json"
docker exec asc-asscor-edge0 bash -c "grep -c 'identity: agent registered' /var/log/asscor-kernel.log"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*' | sort -u | wc -l"