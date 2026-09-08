#!/bin/bash
echo "=== 1. SRD 相关日志 ==="
docker exec asc-asscor-edge0 bash -c "grep -iE 'srd|diffus|reachable|topology' /var/log/asscor-kernel.log | grep -v DEBUG | tail -6"
echo "=== 2. SRD debug 日志 ==="
docker exec asc-asscor-edge0 bash -c "grep -iE 'srd|diffus|topology|edge' /var/log/asscor-kernel.log | grep DEBUG | tail -8"
echo "=== 3. 评估 jsonl 结构 (1 条) ==="
docker exec asc-asscor-edge0 bash -c "head -1 /var/lib/asscor/assessments-20260816.jsonl | python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print(json.dumps({k:v for k,v in d.items() if k not in [\"checks\",\"attck\"]}, ensure_ascii=False)[:600])'" 2>&1
echo "=== 4. jsonl 各主机最近评估 ==="
docker exec asc-asscor-edge0 bash -c "python3 -c \"
import json
hosts={}
for line in open('/var/lib/asscor/assessments-20260816.jsonl'):
    d=json.loads(line)
    hid=d.get('host_id') or d.get('hostId')
    if hid: hosts[hid]=d
for h in sorted(hosts):
    d=hosts[h]
    print(h, 'score=', round(d.get('final_score',0),2), 'acceptable=', d.get('acceptable'), 'checks=', len(d.get('checks',[])))
\"" 2>&1