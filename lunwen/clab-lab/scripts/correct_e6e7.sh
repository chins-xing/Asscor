#!/bin/bash
echo "=== E6 空/缺失输入: kernel 对无 result 心跳的处理 ==="
docker exec asc-asscor-edge0 bash -c "grep -E 'heartbeat received' /var/log/asscor-kernel.log | grep 'has_result.:false' | tail -2"
echo "--- 无 result 时是否触发评估? (应无 assessment) ---"
docker exec asc-asscor-edge0 bash -c "grep 'processing check results' /var/log/asscor-kernel.log | wc -l"
echo "--- 空 result 心跳期间的评估数 (对照) ---"
docker exec asc-asscor-edge0 bash -c "grep -c 'assessment score computed' /var/log/asscor-kernel.log"
echo "=== E6b 域分下限: 全失败域 (OT/RS=0) 是否封顶 ==="
docker exec asc-asscor-edge0 bash -c "grep -oE '\"operation_trust\":[0-9-]+' /var/log/asscor-kernel.log | sort -u | head -3"
echo "=== E7 多风险线性累加验证 (AS 域扣减) ==="
docker exec asc-asscor-edge0 bash -c "grep '"host_id":"host1"' /var/log/asscor-kernel.log | grep -oE 'failed_count[^,]*' | tail -1"
echo "--- AS 域 fail 检查项 delta 清单 (host1 基线) ---"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '\{"check_id":"AS-[0-9]+","domain":"attack_surface","name":"[^"]*","passed":false,"delta":-?[0-9]+' | grep -oE 'AS-[0-9]+.*delta.:-?[0-9]+' | head -8