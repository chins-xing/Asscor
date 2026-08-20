#!/bin/bash
echo "=== kernel 日志最后 15 行 (退出原因) ==="
docker exec asc-asscor-edge0 bash -c "tail -15 /var/log/asscor-kernel.log"
echo "=== edge0 接口 ==="
docker exec asc-asscor-edge0 ip -br addr 2>&1 | head -5
echo "=== edge0 内存 ==="
docker exec asc-asscor-edge0 bash -c "free -m | head -2"
echo "=== host1 容器状态 (是否重启过) ==="
docker inspect asc-asscor-host1 --format '{{.State.Status}} restarts={{.RestartCount}} started={{.State.StartedAt}}' 2>&1
echo "=== 所有容器状态 ==="
docker ps --filter name=asc-asscor --format "{{.Names}} {{.Status}}" | head -20