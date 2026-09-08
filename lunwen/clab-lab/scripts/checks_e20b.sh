#!/bin/bash
echo "=== E20 补验: boundary.conf 改 OKX (30s 间隔内评估) ==="
docker exec asc-asscor-host1 bash -c "printf 'OKX' > /tmp/cu_test/boundary.conf && echo written"
sleep 45
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- CU-003 应 FAIL (OKX 不匹配 ^OK\$) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-003".{0,120}?"passed":(true|false)'
echo "-- 恢复 OK --"
docker exec asc-asscor-host1 bash -c "printf 'OK' > /tmp/cu_test/boundary.conf"
sleep 45
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- CU-003 应恢复 PASS --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-003".{0,120}?"passed":(true|false)'