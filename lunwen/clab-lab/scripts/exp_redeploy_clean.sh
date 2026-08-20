#!/bin/bash
set -e
echo "=== 1. stop all agents ==="
for h in $(seq 1 18); do
  docker exec asc-asscor-host$h bash -c "pkill -x ASSCOR-agent 2>/dev/null || true" 2>/dev/null
done
echo "=== 2. wipe kernel state + restart ==="
docker exec asc-asscor-edge0 bash -c "pkill -x ASSCOR-kernel 2>/dev/null || true; sleep 1; rm -rf /var/lib/asscor/* /etc/asscor/certs/* 2>/dev/null; cd /var/lib/asscor && nohup /usr/local/bin/ASSCOR-kernel --config=/etc/asscor/config.ini --listen=:50051 --cert-dir=/etc/asscor/certs --log-format=json --log-output=/var/log/asscor-kernel.log >/tmp/kernel.out 2>&1 &"
sleep 8
echo "kernel restarted: $(docker exec asc-asscor-edge0 grep -c 'Kernel started' /var/log/asscor-kernel.log 2>/dev/null)"
echo "=== 3. fresh CA + issue host1-18 ==="
rm -rf /tmp/asscor-ca && mkdir -p /tmp/asscor-ca
docker cp asc-asscor-edge0:/etc/asscor/certs/ca.crt /tmp/asscor-ca/ca.crt
docker cp asc-asscor-edge0:/etc/asscor/certs/ca.key /tmp/asscor-ca/ca.key
chmod 600 /tmp/asscor-ca/ca.key
cd /tmp/asscor-ca
for i in $(seq 1 18); do
  openssl req -new -newkey rsa:2048 -nodes -keyout host$i.key -out host$i.csr -subj "/CN=host$i" 2>/dev/null
  printf "extendedKeyUsage = clientAuth\n" > ext$i.cnf
  openssl x509 -req -in host$i.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out host$i.crt -days 365 -extfile ext$i.cnf 2>/dev/null
done
echo "issued host1-18"
echo "=== 4. distribute + start 18 agents ==="
for i in $(seq 1 18); do
  docker exec asc-asscor-host$i bash -c "mkdir -p /etc/asscor/certs /var/log/asscor; pkill -x ASSCOR-agent 2>/dev/null || true"
  docker cp /tmp/ASSCOR-agent asc-asscor-host$i:/usr/local/bin/ASSCOR-agent
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
  docker cp /tmp/agent-dist/agent$i.ini asc-asscor-host$i:/etc/asscor/agent.ini
  docker cp /tmp/asscor-ca/ca.crt asc-asscor-host$i:/etc/asscor/certs/ca.crt
  docker cp /tmp/asscor-ca/host$i.crt asc-asscor-host$i:/etc/asscor/certs/agent.crt
  docker cp /tmp/asscor-ca/host$i.key asc-asscor-host$i:/etc/asscor/certs/agent.key
  docker exec asc-asscor-host$i bash -c "chmod 755 /usr/local/bin/ASSCOR-agent; chmod 600 /etc/asscor/certs/agent.key; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
echo "all 18 agents launched"
sleep 35
echo "=== registration count ==="
docker exec asc-asscor-edge0 grep -c 'identity: agent registered' /var/log/asscor-kernel.log 2>/dev/null
echo "=== heartbeat unique hosts ==="
docker exec asc-asscor-edge0 grep 'heartbeat received' /var/log/asscor-kernel.log 2>/dev/null | grep -oE 'host_id[^,]*' | sort -u | wc -l
echo DONE
