#!/bin/bash
PROXY=http://172.31.0.1:58187
echo "=== 安装 iputils-ping (带代理) ==="
for n in edge0 host1 host2 host3 host4; do
  docker exec -e HTTP_PROXY=$PROXY -e HTTPS_PROXY=$PROXY -e NO_PROXY=localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 asc-asscor-$n bash -c "apt-get update -qq 2>&1 | tail -1 && apt-get install -y -qq iputils-ping 2>&1 | tail -1" &
done
wait
echo "=== 验证 ping 可用 ==="
docker exec asc-asscor-host1 bash -c "which ping && ping -c 1 -W 2 10.10.0.10 2>&1 | tail -2" 2>&1