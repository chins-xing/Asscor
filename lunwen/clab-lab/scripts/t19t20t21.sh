#!/bin/bash
echo ""
echo "===== T19: 路由收敛过程 (断 r1-r4, 收敛窗口内评估) ====="
docker exec asc-asscor-r1 bash -c "ip link set eth4 down"
sleep 1
echo "-- 收敛中立即触发 host6 评估 (网络还在重收敛) --"
docker exec asc-asscor-host6 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 50
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 收敛窗口内评估的 host6 传播边 --"
grep '"host_id":"host6"' /tmp/assessments.jsonl | tail -1 | grep -oE '"source"' | wc -l
echo "-- 网络仍通? (经环冗余) --"
docker exec asc-asscor-host6 ping -c 2 -W 3 10.10.0.10 2>&1 | tail -1
docker exec asc-asscor-r1 bash -c "ip link set eth4 up"
sleep 20

echo ""
echo "===== T20: 拓扑快速连续变化 (r2-r3 抖动 5 次) ====="
echo "-- 抖动前 panic 数 --"
docker exec asc-asscor-edge0 bash -c "grep -c 'panic' /var/log/asscor-kernel.log"
for i in 1 2 3 4 5; do
  docker exec asc-asscor-r2 bash -c "ip link set eth4 down"
  sleep 0.5
  docker exec asc-asscor-r2 bash -c "ip link set eth4 up"
  sleep 0.5
done
echo "-- 抖动后 panic 数 (应不变) --"
docker exec asc-asscor-edge0 bash -c "grep -c 'panic' /var/log/asscor-kernel.log"
echo "-- 抖动后网络恢复 --"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.4.10 2>&1 | tail -1

echo ""
echo "===== T21: 状态变化期间同时评估 (抖动 + 并发评估) ====="
echo "-- 并发评估 host1/4/7/10 (抖动前) --"
for i in 1 4 7 10; do docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.3; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"; done
echo "-- 抖动 4 次 (与评估并发) --"
for i in 1 2 3 4; do
  docker exec asc-asscor-r3 bash -c "ip link set eth5 down"; sleep 0.4
  docker exec asc-asscor-r3 bash -c "ip link set eth5 up"; sleep 0.4
done
sleep 55
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 抖动期并发评估的传播边 (host1/4/7/10) --"
for h in host1 host4 host7 host10; do
  echo -n "$h: "; grep '"host_id":"'$h'"' /tmp/assessments.jsonl | tail -1 | grep -oE '"source"' | wc -l
done
echo "-- 抖动后 panic 数 --"
docker exec asc-asscor-edge0 bash -c "grep -c 'panic' /var/log/asscor-kernel.log"