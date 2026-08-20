#!/bin/bash
echo "===== E20: 边界值翻转 (boundary.conf OK -> OKX) ====="
docker exec asc-asscor-host1 bash -c "printf 'OKX' > /tmp/cu_test/boundary.conf"
echo "等待评估 (30s 间隔)..."; sleep 45
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- CU-003 应 FAIL (不匹配 ^OK\$) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-003","domain":"[^"]*","name":"[^"]*","passed":(true|false),"detail":"[^"]{0,60}'
docker exec asc-asscor-host1 bash -c "printf 'OK' > /tmp/cu_test/boundary.conf"

echo ""
echo "===== E24: 重复执行一致性 (CU-001 多轮) ====="
echo "-- 最近 3 轮 CU-001 --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -3 | grep -oE '"check_id":"CU-001".{0,60}?"passed":(true|false)'

echo ""
echo "===== E27: 动态启停 (删除 CU-002 配置) ====="
docker exec asc-asscor-edge0 bash -c "sed -i '/^\[user_check.fail\]$/,+5d' /etc/asscor/config.ini && echo removed"
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 70
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 重启后 CU-002 是否消失 --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -cE '"check_id":"CU-002"' || echo "CU-002 已消失 (动态停用 OK)"
echo "-- 其他 CU 仍在 --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-[0-9]+"' | sort -u

echo ""
echo "===== E28: 版本变化 (改 CU-001 file_path 指向不存在文件) ====="
docker exec asc-asscor-edge0 bash -c "sed -i 's|file_path = /tmp/cu_test/pass.conf|file_path = /tmp/cu_test/gone.conf|' /etc/asscor/config.ini"
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 70
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- CU-001 应 FAIL (gone.conf 不存在) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"check_id":"CU-001".{0,60}?"passed":(true|false),"detail":"[^"]{0,50}'