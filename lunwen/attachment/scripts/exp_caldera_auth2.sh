#!/bin/bash
echo "=== auth_svc.py ==="
cat /opt/caldera/app/service/auth_svc.py 2>/dev/null | head -50
echo "=== find token file ==="
find /opt/caldera -name '*.token' -o -name '*secret*' -o -name 'auth*' 2>/dev/null | grep -v node_modules | head -8
echo "=== data/objects db files ==="
find /opt/caldera/data -type f 2>/dev/null | head -10
echo DONE
