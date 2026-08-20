#!/bin/bash
KEY="ADMIN123"
echo "=== agents in caldera ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/agents | python3 -c 'import json,sys; d=json.load(sys.stdin); print("agents:", len(d)); [print(" -", a.get("paw"), a.get("host"), a.get("platform")) for a in d]' 2>&1
echo "=== operations ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/operations | python3 -c 'import json,sys; d=json.load(sys.stdin); print("operations:", len(d))' 2>&1
echo "=== planners ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/planners | python3 -c 'import json,sys; d=json.load(sys.stdin); print("planners:", len(d)); [print(" -", p.get("name")) for p in d]' 2>&1
echo "=== objectives ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/objectives | python3 -c 'import json,sys; d=json.load(sys.stdin); print("objectives:", len(d)); [print(" -", o.get("name")) for o in d]' 2>&1
echo DONE
