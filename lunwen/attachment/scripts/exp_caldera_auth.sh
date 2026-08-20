#!/bin/bash
echo "=== try login with default admin/admin ==="
curl -s -m 5 -X POST http://127.0.0.1:8888/api/v2/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | head -c 400
echo
echo "=== try register ==="
curl -s -m 5 -X POST http://127.0.0.1:8888/api/v2/register -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | head -c 400
echo
echo "=== auth source in code ==="
grep -rn 'API_TOKEN\|api_token' /opt/caldera/app/service/auth_svc.py 2>/dev/null | head -6
echo DONE
