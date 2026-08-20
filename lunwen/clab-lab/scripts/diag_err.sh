#!/bin/bash
echo "=== E36 洪泛期间 ERROR 内容 ==="
docker exec asc-asscor-edge0 bash -c "grep '\"level\":\"ERROR\"' /var/log/asscor-kernel.log | tail -2"