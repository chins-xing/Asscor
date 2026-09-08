#!/bin/bash
echo "=== 1. 导出 host2 证书 (冒充用) ==="
docker cp asc-asscor-host2:/etc/asscor/certs/agent.crt /tmp/host2-cert.crt
docker cp asc-asscor-host2:/etc/asscor/certs/agent.key /tmp/host2-cert.key
echo "host2 fp: $(openssl x509 -in /tmp/host2-cert.crt -noout -fingerprint -sha256)"
echo "=== 2. 放入 host1 冒充 ==="
docker cp /tmp/host2-cert.crt asc-asscor-host1:/etc/asscor/certs/agent.crt
docker cp /tmp/host2-cert.key asc-asscor-host1:/etc/asscor/certs/agent.key
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 12
echo "=== 3. kernel 拒绝记录 ==="
docker exec asc-asscor-edge0 bash -c "grep -E 'certificate identity conflict|registration rejected' /var/log/asscor-kernel.log | tail -3"
echo "=== 4. identity 绑定未变 (host1 仍是自己的指纹) ==="
docker exec asc-asscor-edge0 bash -c "cat /var/lib/asscor/heartbeat_identity.json | grep -o 'host1[^\"]*\"[^\"]*'"
echo "=== 5. 恢复 host1 证书 ==="
docker cp /tmp/asscor-ca/host1.crt asc-asscor-host1:/etc/asscor/certs/agent.crt
docker cp /tmp/asscor-ca/host1.key asc-asscor-host1:/etc/asscor/certs/agent.key
docker exec asc-asscor-host1 bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
sleep 12
echo "=== 6. host1 恢复注册 ==="
docker exec asc-asscor-edge0 bash -c "grep 'identity: agent registered' /var/log/asscor-kernel.log | tail -1"