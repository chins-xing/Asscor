#!/bin/bash
echo "=== token in logs ==="
grep -i 'token' /tmp/caldera6.log | head -5
echo "=== token in conf ==="
grep -i 'token\|api_key\|crypt' /opt/caldera/conf/local.yml | head -8
echo "=== data/objects db? ==="
ls /opt/caldera/data/ 2>&1 | head -8
echo DONE
