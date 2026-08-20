#!/bin/bash
for n in edge0 host1 host2 host3 host4 host5 host6 host7 host8 host9 host10 host11 host12; do
  c="asc-asscor-$n"
  eth1=$(docker exec $c ip -br addr show eth1 2>/dev/null | grep -oE '10\.10\.[0-9.]+/[0-9]+' | head -1)
  if [ -z "$eth1" ]; then eth1="NO-ETH1"; fi
  echo "$n: $eth1"
done
echo "=== r routers ==="
for n in r1 r2 r3 r4 r5; do
  c="asc-asscor-$n"
  cnt=$(docker exec $c ip -br addr 2>/dev/null | grep -cE '10\.10\.')
  echo "$n: $cnt internal addrs"
done
echo DONE
