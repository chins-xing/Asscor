#!/bin/bash
echo "=== health ==="
curl -s -m 5 http://127.0.0.1:8888/health; echo
TOKEN=$(grep -oP 'API_TOKEN:\s+\K[^ ]+' /tmp/caldera6.log | head -1)
echo "token: $TOKEN"
echo "=== whoami ==="
curl -s -m 5 -H "KEY: $TOKEN" http://127.0.0.1:8888/api/v2/whoami | head -c 300; echo
echo "=== abilities ==="
curl -s -m 5 -H "KEY: $TOKEN" http://127.0.0.1:8888/api/v2/abilities | python3 -c 'import json,sys; d=json.load(sys.stdin); print("abilities:", len(d))' 2>&1
echo "=== adversaries ==="
curl -s -m 5 -H "KEY: $TOKEN" http://127.0.0.1:8888/api/v2/adversaries | python3 -c 'import json,sys; d=json.load(sys.stdin); print("adversaries:", len(d))' 2>&1
echo "=== facts/agents ==="
curl -s -m 5 -H "KEY: $TOKEN" http://127.0.0.1:8888/api/v2/agents | python3 -c 'import json,sys; d=json.load(sys.stdin); print("agents:", len(d))' 2>&1
echo DONE
