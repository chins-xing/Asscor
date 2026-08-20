#!/bin/bash
echo "=== 彻底杀 kernel ==="
docker exec asc-asscor-edge0 bash -c "for p in \$(pgrep -x ASSCOR-kernel); do kill -9 \$p; done; sleep 3; pgrep -x ASSCOR-kernel >/dev/null && echo 'still alive' || echo 'all dead'; ss -tlnp 2>/dev/null | grep 50051 || echo 'port free'"
echo "=== 干净启动 ==="
docker exec asc-asscor-edge0 bash -c "cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 8
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo RUNNING; grep -c 'Kernel started' /var/log/asscor-kernel.log; ss -tln | grep -c 50051"
echo "=== 等 agent 重连 + 心跳 ==="
sleep 40
echo "--- network info received ---"
docker exec asc-asscor-edge0 bash -c "grep -c 'network info received' /var/log/asscor-kernel.log"
echo "--- 各主机 network 记录 ---"
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*|zone[^,]*|ips[^,]*|subnets[^,]*' | paste - - - - | tail -8"