#!/bin/bash
echo "=== 触发全量评估 (重启 12 agents) ==="
for i in $(seq 1 12); do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &" &
done
wait
sleep 75
echo "=== 评估轮次 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'assessment score computed' /var/log/asscor-kernel.log"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "=== network info 汇总 ==="
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*|ips[^,]*|subnets[^,]*' | paste - - - | tail -12"
echo "=== kernel 稳定性 (错误数) ==="
docker exec asc-asscor-edge0 bash -c "grep -cE '\"level\":\"(ERROR|WARN)\"' /var/log/asscor-kernel.log"