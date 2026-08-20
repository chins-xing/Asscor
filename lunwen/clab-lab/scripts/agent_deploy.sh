#!/bin/bash
set -e
echo "=== 1. 准备 agent 配置 ==="
mkdir -p /tmp/agent-dist
for i in 1 2 3 4; do
  cat > /tmp/agent-dist/agent$i.ini <<EOF
[agent]
kernel_addr = 10.10.0.10:50051
host_id = host$i
hostname = host$i
version = v0.2.3
heartbeat_sec = 30
check_interval_sec = 300
check_timeout_sec = 10
max_retries = 3
reconnect_sec = 5
tls_enabled = true
tls_skip_verify = false
cert_dir = /etc/asscor/certs
hmac_key =
log_format = text
log_level = info
log_output = stderr
EOF
done
echo "=== 2. 分发到 host1-4 ==="
for i in 1 2 3 4; do
  docker exec asc-asscor-host$i bash -c "mkdir -p /etc/asscor/certs /var/log/asscor"
  docker cp /tmp/ASSCOR-agent asc-asscor-host$i:/usr/local/bin/ASSCOR-agent
  docker cp /tmp/agent-dist/agent$i.ini asc-asscor-host$i:/etc/asscor/agent.ini
  docker cp /tmp/asscor-ca/ca.crt asc-asscor-host$i:/etc/asscor/certs/ca.crt
  docker cp /tmp/asscor-ca/host$i.crt asc-asscor-host$i:/etc/asscor/certs/agent.crt
  docker cp /tmp/asscor-ca/host$i.key asc-asscor-host$i:/etc/asscor/certs/agent.key
  docker exec asc-asscor-host$i bash -c "chmod 755 /usr/local/bin/ASSCOR-agent; chmod 600 /etc/asscor/certs/agent.key"
  echo "host$i distributed"
done
echo "=== 3. 启动 4 个 agent ==="
for i in 1 2 3 4; do
  docker exec asc-asscor-host$i bash -c "nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
  echo "host$i started"
done
sleep 15
echo "=== 4. agent 进程 ==="
for i in 1 2 3 4; do
  echo -n "host$i: "; docker exec asc-asscor-host$i bash -c "pgrep -f ASSCOR-agent >/dev/null && echo RUNNING || echo DEAD"
done