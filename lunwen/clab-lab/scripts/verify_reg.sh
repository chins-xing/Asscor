#!/bin/bash
echo "=== identity 绑定 (4 条) ==="
docker exec asc-asscor-edge0 bash -c "cat /var/lib/asscor/heartbeat_identity.json; echo"
echo "=== kernel 注册审计 (4 条) ==="
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*|fingerprint[^,]*|result[^,]*' | paste - - - | tail -4"
echo "=== 心跳统计 ==="
docker exec asc-asscor-edge0 bash -c "grep -c 'heartbeat received' /var/log/asscor-kernel.log"
echo "=== 最近心跳 (各 host) ==="
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*' | sort | uniq -c"