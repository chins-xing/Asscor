#!/bin/bash
echo "=== 启动 kernel ==="
docker cp /tmp/kernel-config.ini asc-asscor-edge0:/etc/asscor/config.ini
docker exec asc-asscor-edge0 bash -c "cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 10
echo "=== 进程与监听 ==="
docker exec asc-asscor-edge0 bash -c "ps aux | grep ASSCOR-kernel | grep -v grep | wc -l; ss -tlnp 2>/dev/null | grep 50051 || echo 'no listen'"
echo "=== 日志 (最后 12 行) ==="
docker exec asc-asscor-edge0 bash -c "tail -12 /var/log/asscor-kernel.log 2>/dev/null || tail -12 /tmp/kernel.out"