#!/bin/bash
echo "========== T5: 节点动态上下线 =========="
echo "--- 下线 host1 agent ---"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent)" 
echo "killed, waiting 75s (超过 60s 心跳超时)..."
sleep 75
echo "--- kernel: agent timed out / pruned ---"
docker exec asc-asscor-edge0 bash -c "grep -E 'agent timed out|pruned dead agent' /var/log/asscor-kernel.log | tail -3"
echo "--- identity 绑定 (应保留 host1) ---"
docker exec asc-asscor-edge0 bash -c "cat /var/lib/asscor/heartbeat_identity.json | grep -o 'host1[^,]*'"
echo "--- 重新上线 host1 ---"
docker exec asc-asscor-host1 bash -c "nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 45
echo "--- host1 重新注册 ---"
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep 'host1' | tail -1"
echo "--- host1 心跳恢复 ---"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep 'host1' | tail -1"
echo ""
echo "========== T8: 单点失效 (kill r1 核心) =========="
docker stop asc-asscor-r1 >/dev/null 2>&1
echo "r1 stopped, waiting 45s..."
sleep 45
echo "--- kernel 是否还收到心跳 (r1 挂 → edge0 与全网断开) ---"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | tail -1"
echo "--- agent 侧状态 (host5) ---"
docker exec asc-asscor-host5 bash -c "tail -3 /var/log/asscor-agent.log 2>/dev/null | grep -E 'error|cycle|retry' | tail -2"
echo "--- 恢复 r1 ---"
docker start asc-asscor-r1 >/dev/null 2>&1
sleep 60
echo "--- 恢复后心跳 ---"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | tail -1"
echo "--- host5 agent 恢复 ---"
docker exec asc-asscor-host5 bash -c "tail -2 /var/log/asscor-agent.log"