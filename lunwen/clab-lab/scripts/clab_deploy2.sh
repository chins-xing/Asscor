#!/bin/bash
cd ~/clab/asscor
sudo containerlab deploy -t asscor.clab.yml 2>&1 | tail -25
echo "=== 节点状态 ==="
sudo containerlab inspect -t asscor.clab.yml 2>/dev/null | tail -20