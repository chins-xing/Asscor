#!/bin/bash
echo "=== full fresh-start banner in log ==="
grep -B2 -A6 'API' /tmp/caldera6.log | head -25
echo "=== try insecure mode (no auth) ==="
# restart with --insecure to bypass auth for API
cd /opt/caldera
sudo pkill -f 'server.py' 2>/dev/null
sleep 2
sudo setsid /opt/caldera/venv/bin/python server.py --fresh --insecure -P sandcat,stockpile,atomic > /tmp/caldera7.log 2>&1 < /dev/null &
disown
sleep 30
echo "=== caldera7 tail ==="
tail -8 /tmp/caldera7.log
echo "=== API without auth ==="
curl -s -m 5 http://127.0.0.1:8888/api/v2/whoami | head -c 200
echo
curl -s -m 5 http://127.0.0.1:8888/api/v2/abilities | python3 -c 'import json,sys; print("abilities:", len(json.load(sys.stdin)))' 2>&1
echo DONE
