#!/bin/bash
echo "===HOME==="
ls -la ~
echo "===LAB-FILES==="
find ~ -maxdepth 3 \( -name "*.clab.yml" -o -name "*.clab.yaml" -o -name "topo*.yml" -o -name "*.topo.yml" \) 2>/dev/null | head -20
echo "===DOCKER==="
docker ps -a 2>/dev/null | head -15
echo "===NET==="
ip -br addr | head -10
echo "===DISK==="
df -h / | tail -1