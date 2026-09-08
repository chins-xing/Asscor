#!/bin/bash
set -e
cd ~/clab/asscor
echo "=== destroy ==="
sudo clab destroy -t asscor.clab.yml 2>&1 | tail -2
echo "=== deploy 24-node ==="
sudo clab deploy -t asscor.clab.yml 2>&1 | grep -cE 'asc-asscor'
echo "=== verify eth1 ==="
docker exec asc-asscor-host1 ls /sys/class/net/ 2>&1 | tr '\n' ' '; echo
echo "=== wait for OSPF + add redistribute ==="
sleep 30
for r in r2 r3 r4 r5; do
  docker exec asc-asscor-$r vtysh -c 'conf t' -c 'router ospf' -c 'redistribute connected' 2>/dev/null
done
sleep 25
echo "=== r1 OSPF routes ==="
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' 2>/dev/null | grep -c 'O>*'
echo "=== host1 -> host9 ping ==="
docker exec asc-asscor-host1 ping -c 2 -W 3 10.10.9.10 2>&1 | tail -1
echo DONE
