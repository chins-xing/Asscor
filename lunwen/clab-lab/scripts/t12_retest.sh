#!/bin/bash
echo "===== T12 补测: 非对称可达性 ====="
docker exec asc-asscor-r2 bash -c "iptables -I FORWARD -s 10.10.1.0/24 -j DROP"
sleep 2
echo "-- A. host1 -> host8 (出向被 DROP) --"
docker exec asc-asscor-host1 bash -c "ping -c 2 -W 2 10.10.8.10; echo exit=\$?"
echo "-- B. host8 -> host1 (反向, 应通) --"
docker exec asc-asscor-host8 bash -c "ping -c 2 -W 2 10.10.1.10; echo exit=\$?"
docker exec asc-asscor-r2 bash -c "iptables -D FORWARD -s 10.10.1.0/24 -j DROP"
echo "cleaned"