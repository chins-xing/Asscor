#!/bin/bash
echo "=== host1(10.10.1.10) -> host3(10.10.3.10) 跨两台路由器 ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.3.10 2>&1 | tail -2
echo "=== host2(10.10.2.10) -> host4(10.10.4.10) ==="
docker exec asc-asscor-host2 ping -c 3 -W 2 10.10.4.10 2>&1 | tail -2
echo "=== host1 -> edge0(10.10.0.10) ==="
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.0.10 2>&1 | tail -2
echo "=== edge0 -> s5720 真实网络网关 192.168.1.1 ==="
docker exec asc-asscor-edge0 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2
echo "=== edge0 -> Windows vEthernet (192.168.1.4) ==="
docker exec asc-asscor-edge0 ping -c 3 -W 2 192.168.1.4 2>&1 | tail -2