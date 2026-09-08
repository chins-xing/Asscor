#!/bin/bash
set -e
cd ~/clab/asscor
echo "=== destroy ==="
sudo clab destroy -t asscor.clab.yml 2>&1 | tail -3
echo "=== deploy fresh ==="
sudo clab deploy -t asscor.clab.yml 2>&1 | tail -6
echo "=== verify eth1 exists now ==="
docker exec asc-asscor-host1 ip -br addr 2>&1 | grep eth1 || echo "STILL-NO-ETH1"
docker exec asc-asscor-host2 ip -br addr 2>&1 | grep eth1 || echo "STILL-NO-ETH1"
echo "=== interfaces in host1 ==="
docker exec asc-asscor-host1 ls /sys/class/net/ 2>&1
echo DONE
