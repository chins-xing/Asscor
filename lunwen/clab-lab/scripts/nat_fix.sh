#!/bin/bash
echo "=== r1 是否有 iptables ==="
docker exec asc-asscor-r1 bash -c "which iptables nft 2>/dev/null; echo ---; ls /usr/sbin/ | grep -E 'iptables|nft' | head -5" 2>&1
echo "=== 加 MASQUERADE (r1 eth0 出口) ==="
docker exec asc-asscor-r1 bash -c "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>&1 && echo iptables-ok" 2>&1
echo "=== 重测 edge0 -> s5720 ==="
docker exec asc-asscor-edge0 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2
echo "=== 重测 host3 -> s5720 (经两跳路由器) ==="
docker exec asc-asscor-host3 ping -c 3 -W 2 192.168.1.1 2>&1 | tail -2