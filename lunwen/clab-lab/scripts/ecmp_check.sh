#!/bin/bash
echo "=== r2 到 host5 子网 10.10.5.0/24 (期望 3 条等价路径 ECMP) ==="
docker exec asc-asscor-r2 vtysh -c "show ip route 10.10.5.0/24" 2>/dev/null | grep -E "via|Known"
echo "=== r2 到 host6 子网 10.10.6.0/24 ==="
docker exec asc-asscor-r2 vtysh -c "show ip route 10.10.6.0/24" 2>/dev/null | grep -E "via|Known"
echo "=== r3 到 host5 子网 ==="
docker exec asc-asscor-r3 vtysh -c "show ip route 10.10.5.0/24" 2>/dev/null | grep "via"
echo "=== ECMP 实际转发验证: 多次 ping 的路径 (mtr/traceroute 替代) ==="
docker exec asc-asscor-r2 bash -c "ip route show 10.10.5.0/24"