#!/bin/bash
echo "===== E31: IPC 中断 (gRPC 流量 DROP) ====="
docker exec asc-asscor-r2 bash -c "iptables -I FORWARD -s 10.10.1.0/24 -d 10.10.0.10 -p tcp --dport 50051 -j DROP && echo ipc-drop-ok"
sleep 30
echo "-- agent 侧 gRPC 中断日志 --"
docker exec asc-asscor-host1 bash -c "tail -6 /var/log/asscor-agent.log | grep -iE 'cycle|error|retry' | tail -2"
echo "-- 恢复 IPC --"
docker exec asc-asscor-r2 bash -c "iptables -D FORWARD -s 10.10.1.0/24 -d 10.10.0.10 -p tcp --dport 50051 -j DROP && echo ipc-restored"
sleep 45
echo "-- 恢复后心跳 --"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'has_result[^,]*'"

echo ""
echo "===== E32: 网络中断 (host1 链路 down) ====="
docker exec asc-asscor-r2 bash -c "ip link set eth2 down && echo link-down"
sleep 40
echo "-- host1 完全断网 (连 kernel 与出网都不通) --"
docker exec asc-asscor-host1 ping -c 1 -W 2 10.10.0.10 2>&1 | tail -1
echo "-- 恢复链路 --"
docker exec asc-asscor-r2 bash -c "ip link set eth2 up && echo link-up"
sleep 55
echo "-- 恢复后心跳+评估 --"
docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'has_result[^,]*'"

echo ""
echo "===== E33: 状态存储不可用 (identity.json 改名) ====="
docker exec asc-asscor-edge0 bash -c "mv /var/lib/asscor/heartbeat_identity.json /var/lib/asscor/heartbeat_identity.json.bak && echo moved"
sleep 10
echo "-- kernel 运行中 (内存绑定仍在) --"
docker exec asc-asscor-edge0 bash -c "pgrep -x ASSCOR-kernel >/dev/null && echo KERNEL-RUNNING"
echo "-- 评估仍正常 (jsonl 可写) --"
docker exec asc-asscor-edge0 bash -c "grep -c 'assessment score computed' /var/log/asscor-kernel.log"
echo "-- 重启 kernel (持久化文件缺失场景) --"
docker exec asc-asscor-edge0 bash -c "kill \$(pgrep -x ASSCOR-kernel) 2>/dev/null; sleep 2; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-level=debug --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 55
echo "-- 重启后 (无 identity 文件): agent 重连注册 (首次绑定?) --"
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'result[^,]*'"
echo "-- 恢复 identity 文件 --"
docker exec asc-asscor-edge0 bash -c "mv /var/lib/asscor/heartbeat_identity.json.bak /var/lib/asscor/heartbeat_identity.json && echo restored"