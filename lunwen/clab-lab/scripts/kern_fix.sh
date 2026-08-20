#!/bin/bash
echo "=== 修 CLI socket 目录并重启 kernel ==="
docker exec asc-asscor-edge0 bash -c "mkdir -p /opt/asscor; kill \$(pgrep ASSCOR-kernel); sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 8
docker exec asc-asscor-edge0 bash -c "tail -3 /var/log/asscor-kernel.log"
echo "=== 证书目录 ==="
docker exec asc-asscor-edge0 bash -c "ls -la /etc/asscor/certs/"
echo "=== agent 证书指纹 ==="
docker exec asc-asscor-edge0 bash -c "openssl x509 -in /etc/asscor/certs/agent.crt -noout -fingerprint -sha256 2>/dev/null || echo 'no agent.crt yet'"