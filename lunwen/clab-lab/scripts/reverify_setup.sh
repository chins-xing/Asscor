#!/bin/bash
cd ~/clab/asscor
echo "=== 部署拓扑 ==="
sudo containerlab deploy -t asscor.clab.yml 2>&1 | grep -cE "INFO .*running"
sleep 35
echo "=== 部署 kernel + 12 agents ==="
bash /tmp/deploy_v3_all.sh 2>&1 | tail -8