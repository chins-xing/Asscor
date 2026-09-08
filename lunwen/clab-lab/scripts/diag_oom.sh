#!/bin/bash
echo "=== host1 容器退出详情 ==="
docker inspect asc-asscor-host1 --format 'OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}} Error={{.State.Error}}' 2>&1
echo "=== host1 最近崩溃日志 (最后退出码) ==="
docker inspect asc-asscor-host1 --format '{{json .State}}' 2>&1 | head -c 400
echo ""
echo "=== WSL 内存现状 ==="
free -h | head -2
echo "=== docker 容器内存统计 (top 8) ==="
docker stats --no-stream --format "{{.Name}} {{.MemUsage}}" 2>/dev/null | sort -k2 -hr | head -8
echo "=== host1 容器最近重启时间线 ==="
docker inspect asc-asscor-host1 --format 'RestartCount={{.RestartCount}} FinishedAt={{.State.FinishedAt}}' 2>&1