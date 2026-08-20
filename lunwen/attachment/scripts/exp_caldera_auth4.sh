#!/bin/bash
echo "=== DefaultLoginHandler ==="
grep -rn 'class DefaultLoginHandler' -A 30 /opt/caldera/app/service/auth_svc.py 2>/dev/null | head -40
echo "=== default creds in code ==="
grep -rn "admin\|password\|ADMIN" /opt/caldera/app/service/auth_svc.py 2>/dev/null | head -10
echo "=== check_permissions / API key usage ==="
grep -rn 'def check_permissions\|api_key\|API_KEY' /opt/caldera/app/service/auth_svc.py 2>/dev/null | head -10
echo DONE
