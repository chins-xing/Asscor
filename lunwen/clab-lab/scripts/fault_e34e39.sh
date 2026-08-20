#!/bin/bash
echo "===== E34: 插件异常 (验证插件健康机制) ====="
echo "-- CLI 插件健康检查 --"
printf "plugin health\nexit\n" | timeout 15 docker exec -i asc-asscor-edge0 /usr/local/bin/ASSCOR-kernel --cli /opt/asscor/asscor-cli.sock 2>/dev/null | grep -E "✓|✗|heartbeat|assessor" | head -6
echo "-- kernel 日志 panic 计数 (插件异常恢复机制) --"
docker exec asc-asscor-edge0 bash -c "grep -c 'panic recovered' /var/log/asscor-kernel.log"

echo ""
echo "===== E36: 重复事件洪泛 (host1 高频心跳 5s) ====="
docker exec asc-asscor-host1 bash -c "sed -i 's/heartbeat_sec = 30/heartbeat_sec = 5/' /etc/asscor/agent.ini"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 40
echo "-- 洪泛期间心跳数 (40s 内应明显增多) --"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep host1 | wc -l"
echo "-- kernel 无 panic/异常 --"
docker exec asc-asscor-edge0 bash -c "grep -cE 'panic|ERROR' /var/log/asscor-kernel.log"
docker exec asc-asscor-host1 bash -c "sed -i 's/heartbeat_sec = 5/heartbeat_sec = 30/' /etc/asscor/agent.ini"

echo ""
echo "===== E35: 插件返回非法数据 (agent 上报异常) ====="
echo "-- 检查 kernel 对异常上报的防护 (超大 packages 截断) --"
docker exec asc-asscor-edge0 bash -c "grep -iE 'exceed|truncat|invalid' /var/log/asscor-kernel.log | tail -3"

echo ""
echo "===== E37-E39: 故障后综合恢复验证 ====="
echo "-- 所有故障恢复后: 全系统评估一轮 --"
for i in 1 5 9 12; do docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.2; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"; done
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 恢复后评估 (host1/5/9/12 分数) --"
for h in host1 host5 host9 host12; do echo -n "$h: "; grep '"host_id":"'$h'"' /tmp/assessments.jsonl | tail -1 | grep -oE '"final_score":[0-9.]+'; done
echo "-- 全系统心跳 (12 台) --"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*' | sort -u | wc -l"
echo "-- 评估响应正常 (E39) --"
docker exec asc-asscor-edge0 bash -c "grep -c 'assessment score computed' /var/log/asscor-kernel.log"