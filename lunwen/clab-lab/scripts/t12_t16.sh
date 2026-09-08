#!/bin/bash
echo "############ 第一批: 拓扑语义 T12-T16 ############"

echo ""
echo "===== T12: 非对称可达性 (r2 阻断 host1 出向) ====="
docker exec asc-asscor-r2 bash -c "iptables -I FORWARD -s 10.10.1.0/24 -j DROP && echo fw-installed"
sleep 3
echo "-- host1 -> host8 (应不通) --"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.8.10 2>&1 | tail -1
echo "-- host8 -> host1 (应通, 非对称) --"
docker exec asc-asscor-host8 ping -c 2 -W 2 10.10.1.10 2>&1 | tail -1
docker exec asc-asscor-r2 bash -c "iptables -D FORWARD -s 10.10.1.0/24 -j DROP && echo fw-removed"

echo ""
echo "===== T13: 不同链路类型 (r2-r3 环加 200ms 延迟) ====="
docker exec asc-asscor-r2 bash -c "tc qdisc add dev eth4 root netem delay 200ms 2>/dev/null && echo tc-ok || echo tc-fail"
sleep 2
echo "-- host1 -> host4 (经 r2-r3 慢链路) --"
docker exec asc-asscor-host1 ping -c 3 -W 3 10.10.4.10 2>&1 | tail -1
echo "-- host1 -> host2 (本地 r2, 无慢链路) --"
docker exec asc-asscor-host1 ping -c 3 -W 2 10.10.2.10 2>&1 | tail -1
docker exec asc-asscor-r2 bash -c "tc qdisc del dev eth4 root 2>/dev/null && echo tc-removed"

echo ""
echo "===== T14: NAT/Firewall/ACL (r2 阻断 host1->host8 子网) ====="
docker exec asc-asscor-r2 bash -c "iptables -I FORWARD -s 10.10.1.0/24 -d 10.10.8.0/24 -j DROP && echo acl-ok"
sleep 3
echo "-- host1 -> host8 (应被 ACL 阻断) --"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.8.10 2>&1 | tail -1
echo "-- host1 -> host5 (应通) --"
docker exec asc-asscor-host1 ping -c 2 -W 2 10.10.5.10 2>&1 | tail -1
docker exec asc-asscor-r2 bash -c "iptables -D FORWARD -s 10.10.1.0/24 -d 10.10.8.0/24 -j DROP && echo acl-removed"

echo ""
echo "===== T15: 跨安全域 (检查 kernel zone 机制) ====="
docker exec asc-asscor-edge0 bash -c "grep -c 'network info received' /var/log/asscor-kernel.log"
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep -oE 'zone[^,]*' | sort | uniq -c | head -5"

echo ""
echo "===== T16: 非最短路径 (确认实际转发路径) ====="
echo "-- host1 -> host8 实际路径 (r2 视角) --"
docker exec asc-asscor-r2 bash -c "vtysh -c 'show ip route 10.10.8.0/24' 2>/dev/null | grep via | head -3"
echo "-- 触发评估采集传播边 (T12-T16 期间) --"
for i in 1 8; do docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 0.5; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"; done
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "collected"