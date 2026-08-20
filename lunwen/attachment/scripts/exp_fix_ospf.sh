#!/bin/bash
echo "=== add redistribute connected to r2-r5 OSPF ==="
for r in r2 r3 r4 r5; do
  docker exec asc-asscor-$r vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected' 2>&1 | head -2
  echo "r$r: redistribute connected added"
done
sleep 30
echo "=== r1 OSPF routes now ==="
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' 2>/dev/null | grep -cE 'O>*'
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' 2>/dev/null | grep -E '10.10.1[3-8]' | head -8
echo "=== host13 -> kernel test ==="
docker exec asc-asscor-host13 ping -c 2 -W 3 10.10.0.10 2>&1 | tail -1
echo DONE
