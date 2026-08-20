#!/bin/bash
echo "=== 拷贝评估数据 ==="
docker cp asc-asscor-edge0:/var/lib/asscor/assessments-20260816.jsonl /tmp/assessments.jsonl
docker cp asc-asscor-edge0:/var/lib/asscor/latest-assessment.json /tmp/latest-assessment.json
docker cp asc-asscor-edge0:/var/lib/asscor/agents-20260816.jsonl /tmp/agents.jsonl
echo "=== WSL python 可用? ==="
python3 --version 2>&1 || python --version 2>&1
echo "=== jsonl 行数 ==="
wc -l /tmp/assessments.jsonl
echo "=== 结构 (首行 key) ==="
head -1 /tmp/assessments.jsonl | python3 -c "import json,sys; print(list(json.loads(sys.stdin.read()).keys()))" 2>&1
echo "=== 各主机最近评估 ==="
python3 - <<'PYEOF'
import json
hosts = {}
for line in open('/tmp/assessments.jsonl'):
    try:
        d = json.loads(line)
    except Exception:
        continue
    hid = d.get('host_id') or d.get('hostId')
    if hid:
        hosts[hid] = d
for h in sorted(hosts):
    d = hosts[h]
    print(f"{h:8s} score={d.get('final_score', d.get('score', 0)):.2f} acceptable={d.get('acceptable')} checks={len(d.get('checks', []))}")
PYEOF