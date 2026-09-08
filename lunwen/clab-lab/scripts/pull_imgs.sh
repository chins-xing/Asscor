#!/bin/bash
echo "=== 拉取 frr + ubuntu ==="
docker pull frrouting/frr:10.1.1 2>&1 | tail -2
docker pull ubuntu:24.04 2>&1 | tail -2
echo "=== 镜像列表 ==="
docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}"