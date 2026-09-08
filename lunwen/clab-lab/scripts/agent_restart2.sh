#!/bin/bash
echo "=== 当前 agent 进程 (pgrep -x) ==="
for i in 1 2 3 4; do
  echo -n "host$i: "; docker exec asc-asscor-host$i bash -c "pgrep -x ASSCOR-agent | tr '\n' ' '"; echo ""
done
echo "=== 正确重启 (pgrep -x) ==="
for i in 1 2 3 4; do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
sleep 20
echo "=== 新进程确认 ==="
for i in 1 2 3 4; do
  echo -n "host$i: "; docker exec asc-asscor-host$i bash -c "pgrep -x ASSCOR-agent >/dev/null && echo RUNNING || echo DEAD"
done
echo "=== agent 日志 ==="
for i in 1 2 3 4; do
  echo "-- host$i --"; docker exec asc-asscor-host$i bash -c "tail -4 /var/log/asscor-agent.log | grep -iE 'register|accepted|session|error' | tail -2"
done