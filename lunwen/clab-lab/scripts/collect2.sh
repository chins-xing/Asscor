#!/bin/bash
echo "=== 1. 重启 kernel (debug 日志) ==="
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 45
echo "=== 2. network info received (8 台) ==="
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*|zone[^,]*|ips[^,]*|subnets[^,]*' | paste - - - - | tail -8"
echo "=== 3. SPC asset zone 更新 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'SPC asset updated' /var/log/asscor-kernel.log"
echo "=== 4. 数据目录 ==="
docker exec asc-asscor-edge0 bash -c "ls -la /var/lib/asscor/ | head -15"