#!/bin/bash
echo "=== 替换默认路由指向 10.10 网关 ==="
docker exec asc-asscor-edge0 bash -c "ip route replace default via 10.10.0.1 dev eth1"
docker exec asc-asscor-host1 bash -c "ip route replace default via 10.10.1.1 dev eth1"
docker exec asc-asscor-host2 bash -c "ip route replace default via 10.10.2.1 dev eth1"
docker exec asc-asscor-host3 bash -c "ip route replace default via 10.10.3.1 dev eth1"
docker exec asc-asscor-host4 bash -c "ip route replace default via 10.10.4.1 dev eth1"
echo "=== host1 路由表确认 ==="
docker exec asc-asscor-host1 ip route 2>&1
echo "=== 重测跨子网 ==="
echo "-- host1 -> host3 --"
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.3.10 2>&1 | tail -2
echo "-- host2 -> host4 --"
docker exec asc-asscor-host2 ping -c 3 -W 2 10.10.4.10 2>&1 | tail -2
echo "-- host1 -> edge0 --"
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.0.10 2>&1 | tail -2
echo "-- edge0 -> s5720 网关 (走内部拓扑) --"
docker exec asc-asscor-edge0 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2