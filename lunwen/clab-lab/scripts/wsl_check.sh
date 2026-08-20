#!/bin/bash
echo "=== docker ==="
systemctl is-active docker 2>/dev/null || echo "docker not active"
docker ps 2>&1 | head -2
echo "=== 拓扑文件 ==="
ls ~/clab/asscor/asscor.clab.yml ~/clab/asscor/frr/r1/frr.conf 2>&1 | head -2
echo "=== 镜像 ==="
docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | head -4
echo "=== 代理测试 (docker hub) ==="
GW=$(ip route show default | awk '{print $3}')
timeout 8 curl -sI -x http://$GW:58187 https://registry-1.docker.io/v2/ -o /dev/null -w "proxy: %{http_code}\n" 2>&1 || echo "proxy fail"