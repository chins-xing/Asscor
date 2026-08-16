#!/bin/bash
echo "========== T6: 路由变化 (断 r2-r3 环) =========="
echo "-- 断开前: r2 到 host6 的 ECMP 路径数 --"
docker exec asc-asscor-r2 bash -c "ip route show 10.10.6.0/24 | grep -c nexthop"
echo "-- 断开 r2-r3 环 (r2 eth4) --"
docker exec asc-asscor-r2 bash -c "ip link set eth4 down"
sleep 15
echo "-- 断开后: r2 到 host6 路径数 (应减少) --"
docker exec asc-asscor-r2 bash -c "ip route show 10.10.6.0/24 | grep -c nexthop"
echo "-- 网络仍通? host1 -> host6 --"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.6.10 2>&1 | tail -1
echo "-- 触发重评估 (重启 host1) --"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "-- 恢复 r2-r3 环 --"
docker exec asc-asscor-r2 bash -c "ip link set eth4 up"
sleep 10
echo "collected"