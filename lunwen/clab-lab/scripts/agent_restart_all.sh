#!/bin/bash
echo "=== 重启 8 个 agent ==="
for i in $(seq 1 8); do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
echo "restarted"
sleep 45
echo "=== debug 级别生效? ==="
docker exec asc-asscor-edge0 bash -c "grep -c '\"level\":\"DEBUG\"' /var/log/asscor-kernel.log || echo 0"
echo "=== network info received ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'network info received' /var/log/asscor-kernel.log || echo 0"
echo "=== 各主机 network 记录 ==="
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*|zone[^,]*|ips[^,]*|subnets[^,]*' | paste - - - - | tail -8"