#!/bin/bash
echo "=== 3. 放入 config.ini 并启动 kernel ==="
docker cp /tmp/kernel-config.ini asc-asscor-edge0:/etc/asscor/config.ini
docker exec asc-asscor-edge0 bash -c "cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --data-dir=/var/lib/asscor --log-format=json --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &" 
sleep 8
echo "=== 4. kernel 状态 ==="
docker exec asc-asscor-edge0 bash -c "ps aux | grep ASSCOR-kernel | grep -v grep | head -2"
echo "--- 日志 ---"
docker exec asc-asscor-edge0 bash -c "tail -20 /var/log/asscor-kernel.log 2>/dev/null || cat /tmp/kernel.out | tail -20"
echo "=== 5. 端口监听 ==="
docker exec asc-asscor-edge0 bash -c "ss -tlnp 2>/dev/null | grep 50051 || netstat -tlnp 2>/dev/null | grep 50051"