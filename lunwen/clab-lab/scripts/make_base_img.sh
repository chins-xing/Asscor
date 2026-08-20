#!/bin/bash
set -e
echo "=== 1. 现有镜像 ==="
docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}"
echo "=== 2. 制作 node base 镜像 (一次性 apt, 之后零下载) ==="
docker rm -f tool-prep 2>/dev/null || true
docker run -d --name tool-prep ubuntu:24.04 sleep 3600 >/dev/null
docker exec -e HTTP_PROXY=http://172.31.0.1:58187 -e HTTPS_PROXY=http://172.31.0.1:58187 tool-prep bash -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq iproute2 iputils-ping ca-certificates >/dev/null 2>&1 && echo prep-done"
docker commit -m "asscor node base: ubuntu24.04 + iproute2/iputils-ping" tool-prep asscor-node:base 2>&1 | tail -1
docker rm -f tool-prep >/dev/null
echo "=== 3. 确认 ==="
docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}" | grep asscor-node