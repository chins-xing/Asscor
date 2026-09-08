#!/bin/bash
KEY="ADMIN123"
echo "=== sandcat plugin files ==="
ls /opt/caldera/plugins/sandcat/payloads/ 2>&1 | head -8
echo "=== get sandcat agent payload endpoint ==="
# sandcat agent is served at /file/download and deployed via the plugin's gocat
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/file/download/sandcat.go 2>&1 | head -c 100
echo
echo "=== api payloads ==="
curl -s -m 5 -H "KEY: $KEY" http://127.0.0.1:8888/api/v2/payloads 2>&1 | python3 -c 'import json,sys; d=json.load(sys.stdin); print([p.get("name") for p in d][:10])' 2>&1
echo DONE
