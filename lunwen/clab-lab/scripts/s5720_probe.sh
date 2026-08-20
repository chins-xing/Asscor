#!/bin/bash
echo "=== WSL 到 s5720 网段连通性 ==="
for ip in 192.168.1.1 192.168.1.4 192.168.1.5; do
  timeout 4 ping -c 2 -W 2 $ip >/dev/null 2>&1 && echo "$ip: PING OK" || echo "$ip: FAIL"
done
echo "=== 路由 ==="
ip route | head -6
echo "=== 外网 (VPN 是否已开) ==="
timeout 10 curl -sI https://registry-1.docker.io/v2/ -o /dev/null -w "docker hub: HTTP %{http_code}\n" 2>&1 || echo "docker hub: FAIL"
timeout 10 curl -sI https://github.com -o /dev/null -w "github: HTTP %{http_code}\n" 2>&1 || echo "github: FAIL"