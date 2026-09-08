#!/bin/bash
cd ~/clab/asscor
echo "=== 关闭 containerlab 拓扑 ==="
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -3
echo "=== 清理临时文件 ==="
rm -f /tmp/assessments.jsonl /tmp/ASSCOR-kernel /tmp/ASSCOR-agent /tmp/kernel-config.ini /tmp/agent-dist/* 2>/dev/null
rm -rf /tmp/asscor-ca /tmp/agent-dist 2>/dev/null
echo "=== 确认容器已清理 ==="
docker ps -a --filter name=asc-asscor --format "{{.Names}}" | wc -l
echo "cleaned"