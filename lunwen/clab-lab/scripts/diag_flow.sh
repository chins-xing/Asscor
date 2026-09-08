#!/bin/bash
echo "=== kernel 日志最近 6 条 ==="
docker exec asc-asscor-edge0 bash -c "tail -6 /var/log/asscor-kernel.log"
echo "=== agent 是否注册/心跳 ==="
docker exec asc-asscor-host1 bash -c "tail -5 /var/log/asscor-agent.log"