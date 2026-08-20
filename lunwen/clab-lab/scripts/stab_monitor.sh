#!/bin/bash
# ASSCOR 7x24 (168h) 稳定性监控 — 每 10 分钟采样一次
# 指标: 心跳累计/评估累计/ERROR 累计/panic 累计/活跃 agent/容器 up
DIR=/tmp/stability
mkdir -p $DIR
CSV=$DIR/stability.csv
PIDFILE=$DIR/monitor.pid
echo "$$" > $PIDFILE
[ -f $CSV ] || echo "ts,heartbeats,assessments,errors,panics,active_agents,containers_up" > $CSV

sampling() {
  local TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local HB=$(docker exec asc-asscor-edge0 bash -c "grep -c 'heartbeat received' /var/log/asscor-kernel.log" 2>/dev/null); [ -z "$HB" ] && HB=NA
  local AS=$(docker exec asc-asscor-edge0 bash -c "grep -c 'assessment score computed' /var/log/asscor-kernel.log" 2>/dev/null); [ -z "$AS" ] && AS=NA
  local ER=$(docker exec asc-asscor-edge0 bash -c "grep -c '\"level\":\"ERROR\"' /var/log/asscor-kernel.log" 2>/dev/null); [ -z "$ER" ] && ER=NA
  local PA=$(docker exec asc-asscor-edge0 bash -c "grep -c 'panic' /var/log/asscor-kernel.log" 2>/dev/null); [ -z "$PA" ] && PA=NA
  local AG=$(docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | grep -oE 'host_id[^,]*' | sort -u | wc -l" 2>/dev/null); [ -z "$AG" ] && AG=NA
  local CT=$(docker ps --filter name=asc-asscor --format "{{.Names}}" | wc -l); [ -z "$CT" ] && CT=NA
  echo "$TS,$HB,$AS,$ER,$PA,$AG,$CT" >> $CSV
  # 记录 ERROR/panic 明细 (仅非零时)
  if [ "$ER" != "0" ] && [ "$ER" != "NA" ]; then
    docker exec asc-asscor-edge0 bash -c "grep '\"level\":\"ERROR\"' /var/log/asscor-kernel.log | tail -3" >> $DIR/errors-$(date -u +%Y%m%d).log 2>/dev/null
  fi
  if [ "$PA" != "0" ] && [ "$PA" != "NA" ]; then
    echo "$TS PANIC-DETECTED" >> $DIR/panics.log
    docker exec asc-asscor-edge0 bash -c "grep 'panic' /var/log/asscor-kernel.log | tail -5" >> $DIR/panics.log 2>/dev/null
  fi
  # 心跳速率 (最近 10 分钟窗口)
  docker exec asc-asscor-edge0 bash -c "grep 'heartbeat received' /var/log/asscor-kernel.log | tail -1200 | wc -l" 2>/dev/null | xargs -I{} echo "$TS rate_hb_window={}" >> $DIR/rate.log
}

# 首采
sampling
# 循环 1008 次 × 600s = 168h
for i in $(seq 1 1008); do
  sleep 600
  sampling
done
echo "monitor-complete" >> $DIR/status.log
