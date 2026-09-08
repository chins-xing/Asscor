#!/bin/bash
cd ~/clab/asscor
echo "=== 部署拓扑 ==="
sudo containerlab deploy -t asscor.clab.yml 2>&1 | tail -35