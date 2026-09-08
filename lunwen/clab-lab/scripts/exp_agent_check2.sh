#!/bin/bash
KEY="ADMIN123"
echo "=== raw agents response ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/agents | head -c 500
echo
echo "=== raw operations ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/operations | head -c 300
echo
echo "=== sandcat still alive? ==="
docker exec asc-asscor-host1 pgrep -f sandcat >/dev/null 2>&1 && echo "SANDCAT-RUNNING" || echo "SANDCAT-DEAD"
docker exec asc-asscor-host1 tail -5 /tmp/sandcat.log 2>&1
echo DONE
