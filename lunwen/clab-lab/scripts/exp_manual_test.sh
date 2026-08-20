#!/bin/bash
echo "=== manual decoyd deploy ==="
docker cp /tmp/decoyd asc-asscor-host2:/tmp/decoyd
docker exec asc-asscor-host2 bash -c 'chmod 755 /tmp/decoyd; pkill -f decoyd 2>/dev/null; nohup /tmp/decoyd 22221,22222 > /tmp/decoyd.log 2>&1 & sleep 1'
echo "--- decoyd log ---"
docker exec asc-asscor-host2 cat /tmp/decoyd.log 2>&1
echo "--- attack from host1 to host2:22222 ---"
docker exec asc-asscor-host1 bash -c 'timeout 2 bash -c "echo > /dev/tcp/10.10.2.10/22222"; echo ATK-EXIT=$?'
sleep 2
echo "--- decoyd hits ---"
docker exec asc-asscor-host2 cat /tmp/decoyd.log 2>&1
echo "--- is 10.10.2.10 the right IP for host2? ---"
docker exec asc-asscor-host2 ip -br addr | grep eth1
echo DONE
