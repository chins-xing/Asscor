#!/bin/bash
PROXY=http://172.31.0.1:58187
echo "=== 安装 iproute2 ==="
for n in edge0 host1 host2 host3 host4; do
  docker exec -e HTTP_PROXY=$PROXY -e HTTPS_PROXY=$PROXY -e NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 asc-asscor-$n bash -c "apt-get install -y -qq iproute2 2>&1 | tail -1" &
done
wait
echo "=== 补配 IP 与默认路由 ==="
docker exec asc-asscor-edge0 bash -c "ip addr add 10.10.0.10/24 dev eth1 2>/dev/null; ip route add default via 10.10.0.1 dev eth1 2>/dev/null; ip -br addr show eth1"
docker exec asc-asscor-host1 bash -c "ip addr add 10.10.1.10/24 dev eth1 2>/dev/null; ip route add default via 10.10.1.1 dev eth1 2>/dev/null; ip -br addr show eth1"
docker exec asc-asscor-host2 bash -c "ip addr add 10.10.2.10/24 dev eth1 2>/dev/null; ip route add default via 10.10.2.1 dev eth1 2>/dev/null; ip -br addr show eth1"
docker exec asc-asscor-host3 bash -c "ip addr add 10.10.3.10/24 dev eth1 2>/dev/null; ip route add default via 10.10.3.1 dev eth1 2>/dev/null; ip -br addr show eth1"
docker exec asc-asscor-host4 bash -c "ip addr add 10.10.4.10/24 dev eth1 2>/dev/null; ip route add default via 10.10.4.1 dev eth1 2>/dev/null; ip -br addr show eth1"
echo "=== r2 接口确认 ==="
docker exec asc-asscor-r2 ip -br addr 2>&1 | grep -E "eth[123]"