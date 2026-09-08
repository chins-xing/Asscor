#!/bin/bash
echo "========== T9/T10/T11 补充数据 =========="
echo "-- 传播边 risk_transmission 值分布 (应固定 0.3 = 无风险加权) --"
docker exec asc-asscor-edge0 bash -c "grep -oE 'risk_transmission\":[0-9.]+' /var/log/asscor-kernel.log | sort | uniq -c | head -5"
echo "-- host2 (差配置) 作为传播源 vs host3 (无配置) — 传播量对比 --"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
grep -oE '"source":"host2"' /tmp/assessments.jsonl | wc -l
grep -oE '"source":"host3"' /tmp/assessments.jsonl | wc -l
echo "-- 评估性能: 单轮评估耗时 (最近 12 条 assessment 时间戳跨度) --"
docker exec asc-asscor-edge0 bash -c "grep 'assessment score computed' /var/log/asscor-kernel.log | grep -oE '\"time\":\"[^\"]+' | tail -12 | head -1; grep 'assessment score computed' /var/log/asscor-kernel.log | grep -oE '\"time\":\"[^\"]+' | tail -1"
echo "-- T11: kernel 崩溃/panic 数 --"
docker exec asc-asscor-edge0 bash -c "grep -cE 'panic|FATAL' /var/log/asscor-kernel.log"
echo "-- 拓扑数据量: propagation_edges 总条数 (最后一条评估) --"
docker exec asc-asscor-edge0 bash -c "grep -oE 'propagation_edges' /tmp/assessments.jsonl | wc -l"
echo "-- 心跳总量 --"
docker exec asc-asscor-edge0 bash -c "grep -c 'heartbeat received' /var/log/asscor-kernel.log"