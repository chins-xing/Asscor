#!/bin/bash
set -e
cd /opt/caldera
sudo pkill -f 'server.py' 2>/dev/null
sleep 2
sudo setsid /opt/caldera/venv/bin/python server.py --fresh -P sandcat,stockpile,atomic > /tmp/caldera6.log 2>&1 < /dev/null &
disown
echo "started, waiting 30s..."
sleep 30
echo "=== caldera6.log tail ==="
tail -25 /tmp/caldera6.log
echo "=== ports ==="
ss -tln | grep -E '8888|8443' || echo NOT-LISTENING
echo DONE
