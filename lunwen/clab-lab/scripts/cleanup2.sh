#!/bin/bash
cd ~/clab/asscor
echo "=== 关闭 containerlab 拓扑 ==="
sudo containerlab destroy -t asscor.clab.yml -c 2>&1 | tail -2
echo "=== 清理临时文件 ==="
rm -f /tmp/assessments.jsonl /tmp/ASSCOR-kernel /tmp/ASSCOR-agent /tmp/kernel-config.ini /tmp/deploy_v3_all.sh /tmp/*.sh 2>/dev/null
docker ps -a --filter name=asc-asscor --format "{{.Names}}" | wc -l
echo "cleaned"