#!/bin/bash
TOKEN=$(grep -oP 'API_TOKEN:\s+\K[^ ]+' /tmp/caldera6.log | head -1)
echo "token: $TOKEN"
echo "=== raw health ==="
curl -sv -m 5 http://127.0.0.1:8888/health 2>&1 | tail -8
echo "=== raw whoami ==="
curl -s -m 5 -H "KEY: $TOKEN" http://127.0.0.1:8888/api/v2/whoami | head -c 500
echo
echo "=== raw abilities (first 200 chars) ==="
curl -s -m 5 -H "KEY: $TOKEN" http://127.0.0.1:8888/api/v2/abilities | head -c 200
echo
echo DONE
