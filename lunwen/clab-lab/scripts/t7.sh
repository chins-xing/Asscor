#!/bin/bash
echo "========== T7: 服务迁移 (host1 agent 迁移到 host9 容器) =========="
echo "-- 迁移前: host1 上报的子网 --"
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'subnets[^}]*'"
echo "-- 停止原 host1 agent --"
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null"
echo "-- host9 容器内启动 host1 身份的 agent (host1 证书) --"
docker cp /tmp/asscor-ca/host1.crt asc-asscor-host9:/etc/asscor/certs/agent.crt
docker cp /tmp/asscor-ca/host1.key asc-asscor-host9:/etc/asscor/certs/agent.key
docker cp /tmp/agent-dist/agent1.ini asc-asscor-host9:/etc/asscor/agent.ini
docker exec asc-asscor-host9 bash -c "chmod 600 /etc/asscor/certs/agent.key; kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 50
echo "-- 迁移后: host1 重新注册 (同身份同证书) --"
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | grep host1 | tail -1"
echo "-- 迁移后: host1 上报的子网 (应变为 host9 的 10.10.9.0/24) --"
docker exec asc-asscor-edge0 bash -c "grep 'network info received' /var/log/asscor-kernel.log | grep host1 | tail -1 | grep -oE 'subnets[^}]*'"
echo "-- identity 绑定 (host1 指纹应不变) --"
docker exec asc-asscor-edge0 bash -c "grep -o '\"host1\":\"[a-f0-9]\{8\}' /var/lib/asscor/heartbeat_identity.json"
echo "-- 恢复: host9 归还 host1 证书, 恢复原状 --"
docker cp /tmp/asscor-ca/host9.crt asc-asscor-host9:/etc/asscor/certs/agent.crt
docker cp /tmp/asscor-ca/host9.key asc-asscor-host9:/etc/asscor/certs/agent.key
docker cp /tmp/agent-dist/agent9.ini asc-asscor-host9:/etc/asscor/agent.ini
docker exec asc-asscor-host9 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
docker exec asc-asscor-host1 bash -c "nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
echo "restored"