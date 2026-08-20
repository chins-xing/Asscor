#!/bin/bash
echo "===== E12 补验: host1 重新绑定恢复 ====="
docker exec asc-asscor-edge0 bash -c "grep -o '\"host1\":\"[a-f0-9]\{8\}' /var/lib/asscor/heartbeat_identity.json"
echo "-- host1 注册审计 (删除后重注册) --"
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep '\"host_id\":\"host1\"' | tail -1"

echo ""
echo "===== E15: 并发评估 12 资产 × 3 轮 (压力) ====="
for round in 1 2 3; do
  for i in $(seq 1 12); do docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.2; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &" & done
  wait
  sleep 55
done
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 评估轮次总数 --"
grep -c '"final_score"' /tmp/assessments.jsonl
echo "-- panic 数 --"
docker exec asc-asscor-edge0 bash -c "grep -c 'panic' /var/log/asscor-kernel.log"
echo "-- 12 台最近分数 (并发无串扰) --"
grep -oE '"host_id":"host[0-9]+","hostname":"host[0-9]+","final_score":[0-9.]+' /tmp/assessments.jsonl | tail -12 | awk -F'"' '{print $4, $8}'

echo ""
echo "===== E16: 同一资产 (host1) 连续多次评估 ====="
echo "-- 缩短 host1 检查间隔到 10s --"
docker exec asc-asscor-host1 bash -c "sed -i 's/check_interval_sec = 300/check_interval_sec = 10/' /etc/asscor/agent.ini"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 40
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host1 最近 4 次评估分数 (应一致) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -4 | grep -oE '"final_score":[0-9.]+'
docker exec asc-asscor-host1 bash -c "sed -i 's/check_interval_sec = 10/check_interval_sec = 300/' /etc/asscor/agent.ini"
echo "(间隔恢复 300s)"

echo ""
echo "===== E17: 交错评估 A(host1)/B(host2) × 2 ====="
for pair in 1 2; do
  docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.2; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
  sleep 50
  docker exec asc-asscor-host2 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.2; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
  sleep 50
done
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 交错序列 (host1/host2 交替评估时间) --"
grep -E '"host_id":"host[12]"' /tmp/assessments.jsonl | tail -8 | grep -oE '"host_id":"host[12]"|"final_score":[0-9.]+' | paste - - 
echo "-- 交错后分数 (无串扰: 两资产分数独立且一致) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+'
grep '"host_id":"host2"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+'