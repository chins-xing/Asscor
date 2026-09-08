#!/bin/bash
echo "=== 1. kernel config.ini 追加 user_check 段 ==="
docker exec asc-asscor-edge0 bash -c "cat >> /etc/asscor/config.ini <<'EOF'

[user_check.pass]
id = CU-001
domain = operation_trust
name = PASS测试
file_path = /tmp/cu_test/pass.conf

[user_check.fail]
id = CU-002
domain = operation_trust
name = FAIL测试
file_path = /tmp/cu_test/fail.conf

[user_check.boundary]
id = CU-003
domain = operation_trust
name = 边界测试
file_path = /tmp/cu_test/boundary.conf
file_regex = ^OK$

[user_check.execexcept]
id = CU-004
domain = operation_trust
name = 执行异常测试
command = systemctl is-active nope

[user_check.empty]
id = CU-005
domain = operation_trust
name = 空输出测试
command = ss -l
EOF
echo appended"
echo "=== 2. 重启 kernel (使 user_check 生效) ==="
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 50
echo "=== 3. host1 建立测试文件 (PASS 文件存在; FAIL 文件缺失; 边界 OK) ==="
docker exec asc-asscor-host1 bash -c "mkdir -p /tmp/cu_test && touch /tmp/cu_test/pass.conf && printf 'OK' > /tmp/cu_test/boundary.conf && ls -la /tmp/cu_test/"
echo "=== 4. 触发 host1 评估 ==="
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "=== 5. user_check 结果 (CU-001~005) ==="
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '\{"check_id":"CU-[0-9]+","domain":"[^"]*","name":"[^"]*","passed":(true|false),"delta":[0-9-]+,"detail":"[^"]*"' | head -6