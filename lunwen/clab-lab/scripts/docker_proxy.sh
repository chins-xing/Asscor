#!/bin/bash
echo "=== 配置 dockerd 代理 ==="
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/http-proxy.conf >/dev/null <<'EOF'
[Service]
Environment="HTTP_PROXY=http://172.31.0.1:58187"
Environment="HTTPS_PROXY=http://172.31.0.1:58187"
Environment="NO_PROXY=localhost,127.0.0.1,172.31.0.0/20,172.17.0.0/16,192.168.1.0/24"
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
sleep 4
systemctl is-active docker
echo "=== 测试拉取 (alpine 小镜像) ==="
timeout 120 docker pull alpine:3.20 2>&1 | tail -4