#!/bin/bash
echo "=== ERROR/WARN 分类统计 ==="
docker exec asc-asscor-edge0 bash -c "grep -E '\"level\":\"(ERROR|WARN)\"' /var/log/asscor-kernel.log | grep -oE '\"msg\":\"[^\"]+' | sort | uniq -c | sort -rn | head -12"