#!/bin/bash
GW=$(ip route show default | awk '{print $3}')
echo "Windows 宿主 (WSL 网关): $GW"
echo "=== TCP 连通 58187 ==="
timeout 5 bash -c "echo > /dev/tcp/$GW/58187" 2>/dev/null && echo "port 58187: TCP OPEN" || echo "port 58187: CLOSED/UNREACHABLE"
echo "=== HTTP 代理测试 ==="
timeout 12 curl -sI -x http://$GW:58187 https://registry-1.docker.io/v2/ -o /dev/null -w "docker hub via HTTP proxy: %{http_code} (%{time_total}s)\n" 2>&1 || echo "HTTP proxy: FAIL"
echo "=== SOCKS5 代理测试 ==="
timeout 12 curl -sI --socks5-hostname $GW:58187 https://registry-1.docker.io/v2/ -o /dev/null -w "docker hub via SOCKS5: %{http_code} (%{time_total}s)\n" 2>&1 || echo "SOCKS5: FAIL"
echo "=== github 测试 ==="
timeout 12 curl -sI -x http://$GW:58187 https://github.com -o /dev/null -w "github via proxy: %{http_code} (%{time_total}s)\n" 2>&1 || echo "github: FAIL"