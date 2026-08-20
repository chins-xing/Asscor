#!/bin/bash
echo "=== 文件存在性 ==="
docker exec asc-asscor-edge0 ls -la /usr/local/bin/ASSCOR-kernel /etc/asscor/config.ini 2>&1
echo "=== kernel 进程 ==="
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo RUNNING || echo DEAD"
echo "=== 启动日志 ==="
docker exec asc-asscor-edge0 bash -c "tail -25 /var/log/asscor-kernel.log 2>/dev/null || tail -25 /tmp/kernel.out"