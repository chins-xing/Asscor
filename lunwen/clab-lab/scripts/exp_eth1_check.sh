#!/bin/bash
echo "=== eth1 status across all hosts ==="
for n in edge0 host1 host2 host3 host4 host5 host6 host7 host8 host9 host10 host11 host12 host13 host14 host15 host16 host17 host18; do
  c="asc-asscor-$n"
  has=$(docker exec $c ls /sys/class/net/ 2>/dev/null | grep -c eth1)
  echo "$n: eth1=$has"
done
echo DONE
