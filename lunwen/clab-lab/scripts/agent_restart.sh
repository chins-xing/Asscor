#!/bin/bash
echo "=== 重启 agent (显式 cert-dir) ==="
for i in 1 2 3 4; do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -f ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
sleep 20
echo "=== agent 日志 (注册结果) ==="
for i in 1 2 3 4; do
  echo "-- host$i --"
  docker exec asc-asscor-host$i bash -c "tail -5 /var/log/asscor-agent.log 2>/dev/null | grep -iE 'register|accepted|error' | tail -2"
done
echo "=== kernel: identity 绑定 ==="
docker exec asc-asscor-edge0 bash -c "cat /var/lib/asscor/heartbeat_identity.json 2>/dev/null; echo"
echo "=== kernel: 注册审计 ==="
docker exec asc-asscor-edge0 bash -c "grep -E 'identity: agent registered' /var/log/asscor-kernel.log | tail -4"