#!/bin/bash
echo "=== 重建差异文件 ==="
docker exec asc-asscor-host1 bash -c "mkdir -p /etc/ssh && printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config && cat /etc/ssh/sshd_config && echo host1-ok"
docker exec asc-asscor-host2 bash -c "mkdir -p /etc/ssh && printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n' > /etc/ssh/sshd_config && echo host2-bad"
echo "=== 重启 host1/2/3 agent ==="
for i in 1 2 3; do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "collected"