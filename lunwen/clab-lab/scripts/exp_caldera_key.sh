#!/bin/bash
echo "=== api_key in config ==="
grep -n 'api_key' /opt/caldera/conf/local.yml /opt/caldera/conf/default.yml 2>/dev/null
echo "=== verify_hash function ==="
grep -rn 'def verify_hash' -A 8 /opt/caldera/app/utility/*.py 2>/dev/null | head -12
echo DONE
