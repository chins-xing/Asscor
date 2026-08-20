#!/bin/bash
echo "=== kernel 进程 ==="
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo RUNNING || echo DEAD"
echo "=== /tmp/kernel.out ==="
docker exec asc-asscor-edge0 bash -c "tail -8 /tmp/kernel.out 2>/dev/null"
echo "=== 端口 ==="
docker exec asc-asscor-edge0 bash -c "ss -tlnp 2>/dev/null | grep 50051 || echo 'no listen'"