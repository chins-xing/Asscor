#!/bin/bash
echo "=== 删除 r2/r3 mgmt 默认路由 ==="
docker exec asc-asscor-r2 bash -c "ip route del default 2>&1; ip route add default via 10.10.200.1 dev eth1 2>&1; ip route show default"
docker exec asc-asscor-r3 bash -c "ip route del default 2>&1; ip route add default via 10.10.200.5 dev eth1 2>&1; ip route show default"
echo "=== 重测 ==="
echo "-- host3 -> s5720 --"
docker exec asc-asscor-host3 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2
echo "-- host2 -> s5720 --"
docker exec asc-asscor-host2 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2
echo "-- host4 -> s5720 --"
docker exec asc-asscor-host4 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2