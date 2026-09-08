#!/bin/bash
echo "=== host9 decoyd process ==="
docker exec asc-asscor-host9 ps aux 2>/dev/null | grep -i decoy | grep -v grep || echo "NO-DECOYD"
echo "=== host9 listening ports ==="
docker exec asc-asscor-host9 ss -tln 2>/dev/null | grep -E '22222|22221' || echo "NO-LISTEN"
echo "=== host9 decoyd log ==="
docker exec asc-asscor-host9 ls -la /tmp/decoyd*.log 2>&1 | head -3
docker exec asc-asscor-host9 cat /tmp/decoyd-1.log 2>&1 | head -5
echo "=== host1 -> host9:22222 direct test ==="
docker exec asc-asscor-host1 bash -c 'timeout 2 bash -c "echo test > /dev/tcp/10.10.9.10/22222" 2>&1; echo EXIT=$?'
echo DONE
