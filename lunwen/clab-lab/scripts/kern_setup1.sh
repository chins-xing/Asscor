#!/bin/bash
set -e
echo "=== 1. 拷贝 kernel 二进制到 edge0 ==="
docker cp /tmp/ASSCOR-kernel asc-asscor-edge0:/usr/local/bin/ASSCOR-kernel
docker exec asc-asscor-edge0 chmod 755 /usr/local/bin/ASSCOR-kernel
docker exec asc-asscor-edge0 ls -la /usr/local/bin/ASSCOR-kernel
echo "=== 2. 配置目录 ==="
docker exec asc-asscor-edge0 bash -c "mkdir -p /etc/asscor /var/lib/asscor /etc/asscor/certs"