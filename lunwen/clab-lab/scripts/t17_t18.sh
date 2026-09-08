#!/bin/bash
echo "############ 第二批: 动态性 T17-T21 ############"

echo ""
echo "===== T17: 节点下线 (观察拓扑残留) ====="
echo "-- 记录当前评估中 host3 作为传播源的次数 --"
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
grep -oE '"source":"host3"' /tmp/assessments.jsonl | wc -l
echo "-- 下线 host3 agent --"
docker exec asc-asscor-host3 bash -c "kill \$(pgrep -x ASSCOR-agent)"
sleep 75
echo "-- host3 心跳超时? --"
docker exec asc-asscor-edge0 bash -c "grep -E 'agent timed out' /var/log/asscor-kernel.log | tail -1"
echo "-- 触发 host1 评估 (host3 已下线) --"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host3 下线后, host1 新评估中 host3 是否仍是传播源 (拓扑残留?) --"
grep '"host_id":"host1"' /tmp/assessments.jsonl | tail -1 | grep -oE '"source":"host3"' | wc -l
echo "-- 恢复 host3 --"
docker exec asc-asscor-host3 bash -c "nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 40
echo ""
echo "===== T18: 边动态删除 (断 r3-r4 环) ====="
docker exec asc-asscor-r3 bash -c "ip link set eth5 down"
sleep 15
echo "-- 断链后 r3 到 host5 子网路径变化 --"
docker exec asc-asscor-r3 bash -c "vtysh -c 'show ip route 10.10.5.0/24' 2>/dev/null | grep via | head -2"
echo "-- 触发 host5 评估 --"
docker exec asc-asscor-host5 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- host5 新评估传播边数 (应仍 11?) --"
grep '"host_id":"host5"' /tmp/assessments.jsonl | tail -1 | grep -oE '"source"' | wc -l
docker exec asc-asscor-r3 bash -c "ip link set eth5 up"
echo "restored r3-r4"