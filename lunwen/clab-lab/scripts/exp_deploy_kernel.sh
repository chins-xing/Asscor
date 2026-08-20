#!/bin/bash
echo "=== edge0 binary ==="
docker exec asc-asscor-edge0 ls -la /usr/local/bin/ASSCOR-kernel 2>&1 || echo "NO-BINARY"
echo "=== edge0 dirs ==="
docker exec asc-asscor-edge0 ls /etc/asscor /var/lib/asscor 2>&1 | head -8
echo "=== copy kernel ==="
docker exec asc-asscor-edge0 bash -c "mkdir -p /etc/asscor /var/lib/asscor /etc/asscor/certs /var/log" 2>&1
docker cp /tmp/ASSCOR-kernel asc-asscor-edge0:/usr/local/bin/ASSCOR-kernel
docker cp /tmp/kernel-config.ini asc-asscor-edge0:/etc/asscor/config.ini
docker exec asc-asscor-edge0 bash -c "chmod 755 /usr/local/bin/ASSCOR-kernel; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 8
echo "kernel started: $(docker exec asc-asscor-edge0 grep -c 'Kernel started' /var/log/asscor-kernel.log 2>/dev/null)"
echo "port: $(docker exec asc-asscor-edge0 ss -tln 2>/dev/null | grep -c 50051)"
echo DONE
