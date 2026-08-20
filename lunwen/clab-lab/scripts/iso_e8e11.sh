#!/bin/bash
echo "############ 状态隔离实验 E8-E17 ############"
echo ""
echo "===== E8: A/B 两资产同时评估 ====="
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.3; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
docker exec asc-asscor-host2 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.3; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host1/host2 最新评估 --"
for h in host1 host2; do grep '"host_id":"'$h'"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"attack_surface":[0-9]+|"prism_score":[0-9.]+'; done

echo ""
echo "===== E9: A 高风险, B 低风险并发评估 ====="
echo "-- A(host1) 制造高风险: 坏 sshd_config --"
docker exec asc-asscor-host1 bash -c "printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n' > /etc/ssh/sshd_config"
echo "-- B(host2) 低风险: 良好 sshd_config --"
docker exec asc-asscor-host2 bash -c "mkdir -p /etc/ssh && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.3; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
docker exec asc-asscor-host2 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.3; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 并发评估结果 (期望 A 低分/AS 域低, B 高分/AS 域高, 互不影响) --"
for h in host1 host2; do echo "[$h]"; grep '"host_id":"'$h'"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"attack_surface":[0-9]+|"operation_trust":[0-9]+'; done

echo ""
echo "===== E10: A 评估失败, B 正常评估 ====="
echo "-- A(host1) 断连 (kill agent 不重启, 制造失败) --"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent)"
echo "-- B(host2) 正常触发评估 --"
docker exec asc-asscor-host2 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.3; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- B(host2) 在 A 失败期间是否正常评估? --"
grep '"host_id":"host2"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+|"attack_surface":[0-9]+'
echo "-- A(host1) 失败期间无新评估 (最后一条时间) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"timestamp":"[^"]*"|"final_score":[0-9.]+'
echo "-- B 的评估是否被 A 失败污染? (B 应仍为低风险高分) --"
grep '"host_id":"host2"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+'

echo ""
echo "===== E11: A 重评估, B 不重评估 ====="
echo "-- 记录 B(host2) 当前评估时间戳 --"
B_TS=$(grep '"host_id":"host2"' /tmp/assessments.jsonl | tail -1 | grep -oE '"timestamp":"[^"]*"')
echo "B before: $B_TS"
echo "-- 只重启 A(host1) 触发重评估 --"
docker exec asc-asscor-host1 bash -c "nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
B_TS2=$(grep '"host_id":"host2"' /tmp/assessments.jsonl | tail -1 | grep -oE '"timestamp":"[^"]*"')
echo "B after:  $B_TS2"
[ "$B_TS" = "$B_TS2" ] && echo "B 未重评估 (时间戳不变) OK" || echo "B 被重评估?!"
A_TS=$(grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"timestamp":"[^"]*"')
echo "A after:  $A_TS (重评估)"