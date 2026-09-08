#!/bin/bash
echo "=== 制造主机差异 (零下载) ==="
# host1: 良好的 SSH 强认证配置
docker exec asc-asscor-host1 bash -c "printf 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\n' > /etc/ssh/sshd_config; echo host1-sshd-ok"
# host2: 允许 root 密码登录 (差配置)
docker exec asc-asscor-host2 bash -c "printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n' > /etc/ssh/sshd_config; echo host2-sshd-bad"
# host3-8: 无文件 (保持)
echo "=== 重启 host1/2/3 agent 触发评估 ==="
for i in 1 2 3; do
  docker exec asc-asscor-host$i bash -c "kill \$(pgrep -x ASSCOR-agent) 2>/dev/null; sleep 1; nohup /usr/local/bin/ASSCOR-agent --config=/etc/asscor/agent.ini --kernel=10.10.0.10:50051 --cert-dir=/etc/asscor/certs --log-output=/var/log/asscor-agent.log >/tmp/agent.out 2>&1 &"
done
sleep 60
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
echo "collected"