#!/bin/bash
# Re-run the topology exec commands manually to restore internal networks
# (eth1 IP + routes) without destroying containers.
echo "=== edge0 ==="
docker exec asc-asscor-edge0 bash -c "ip addr add 10.10.0.10/24 dev eth1 2>/dev/null; ip route replace default via 10.10.0.1 dev eth1 2>/dev/null || true" 2>&1
echo "=== r1 (core router) ==="
docker exec asc-asscor-r1 bash -c "ip addr add 10.10.0.1/24 dev eth1 2>/dev/null; ip addr add 10.10.200.1/30 dev eth2 2>/dev/null; ip addr add 10.10.200.5/30 dev eth3 2>/dev/null; ip addr add 10.10.200.9/30 dev eth4 2>/dev/null; ip addr add 10.10.200.13/30 dev eth5 2>/dev/null || true" 2>&1
echo "=== r2 ==="
docker exec asc-asscor-r2 bash -c "ip addr add 10.10.200.2/30 dev eth1 2>/dev/null; ip addr add 10.10.1.1/24 dev eth2 2>/dev/null; ip addr add 10.10.2.1/24 dev eth3 2>/dev/null; ip addr add 10.10.200.17/30 dev eth4 2>/dev/null; ip addr add 10.10.200.30/30 dev eth5 2>/dev/null; ip addr add 10.10.9.1/24 dev eth6 2>/dev/null; ip route del default 2>/dev/null; ip route add default via 10.10.200.1 dev eth1 2>/dev/null || true" 2>&1
echo "=== r3 ==="
docker exec asc-asscor-r3 bash -c "ip addr add 10.10.200.6/30 dev eth1 2>/dev/null; ip addr add 10.10.3.1/24 dev eth2 2>/dev/null; ip addr add 10.10.4.1/24 dev eth3 2>/dev/null; ip addr add 10.10.200.18/30 dev eth4 2>/dev/null; ip addr add 10.10.200.21/30 dev eth5 2>/dev/null; ip addr add 10.10.10.1/24 dev eth6 2>/dev/null; ip route del default 2>/dev/null; ip route add default via 10.10.200.5 dev eth1 2>/dev/null || true" 2>&1
echo "=== r4 ==="
docker exec asc-asscor-r4 bash -c "ip addr add 10.10.200.10/30 dev eth1 2>/dev/null; ip addr add 10.10.5.1/24 dev eth2 2>/dev/null; ip addr add 10.10.6.1/24 dev eth3 2>/dev/null; ip addr add 10.10.200.22/30 dev eth4 2>/dev/null; ip addr add 10.10.200.25/30 dev eth5 2>/dev/null; ip addr add 10.10.11.1/24 dev eth6 2>/dev/null; ip route del default 2>/dev/null; ip route add default via 10.10.200.9 dev eth1 2>/dev/null || true" 2>&1
echo "=== r5 ==="
docker exec asc-asscor-r5 bash -c "ip addr add 10.10.200.14/30 dev eth1 2>/dev/null; ip addr add 10.10.7.1/24 dev eth2 2>/dev/null; ip addr add 10.10.8.1/24 dev eth3 2>/dev/null; ip addr add 10.10.200.26/30 dev eth4 2>/dev/null; ip addr add 10.10.200.29/30 dev eth5 2>/dev/null; ip addr add 10.10.12.1/24 dev eth6 2>/dev/null; ip route del default 2>/dev/null; ip route add default via 10.10.200.13 dev eth1 2>/dev/null || true" 2>&1
echo "=== hosts 1-12 ==="
declare -A HOSTIPS=( [host1]="10.10.1.10/24 10.10.1.1" [host2]="10.10.2.10/24 10.10.2.1" [host3]="10.10.3.10/24 10.10.3.1" [host4]="10.10.4.10/24 10.10.4.1" [host5]="10.10.5.10/24 10.10.5.1" [host6]="10.10.6.10/24 10.10.6.1" [host7]="10.10.7.10/24 10.10.7.1" [host8]="10.10.8.10/24 10.10.8.1" [host9]="10.10.9.10/24 10.10.9.1" [host10]="10.10.10.10/24 10.10.10.1" [host11]="10.10.11.10/24 10.10.11.1" [host12]="10.10.12.10/24 10.10.12.1" )
for h in host1 host2 host3 host4 host5 host6 host7 host8 host9 host10 host11 host12; do
  read IP GW <<< "${HOSTIPS[$h]}"
  docker exec asc-asscor-$h bash -c "ip addr add $IP dev eth1 2>/dev/null; ip route replace default via $GW dev eth1 2>/dev/null || true"
done
echo "=== verify ==="
docker exec asc-asscor-host1 ip -br addr | grep eth1
docker exec asc-asscor-host2 ip -br addr | grep eth1
echo "=== restart FRR for OSPF ==="
for r in r1 r2 r3 r4 r5; do
  docker exec asc-asscor-$r bash -c "(sleep 2; /usr/lib/frr/frrinit.sh start) >/tmp/frr-init.log 2>&1 &"
done
sleep 30
echo "=== OSPF check ==="
docker exec asc-asscor-r1 vtysh -c 'show ip route ospf' 2>/dev/null | grep -c 'O>*'
echo "=== cross-subnet ping host1->host2 ==="
docker exec asc-asscor-host1 ping -c 2 -W 3 10.10.2.10 2>&1 | tail -1
echo DONE
