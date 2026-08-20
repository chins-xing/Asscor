#!/bin/bash
# Kill any existing caldera
sudo pkill -f 'server.py' 2>/dev/null
sleep 2
# Start fully detached with setsid
cd /opt/caldera
sudo setsid /opt/caldera/venv/bin/python server.py --fresh > /tmp/caldera2.log 2>&1 < /dev/null &
disown
echo "started, waiting 25s..."
sleep 25
echo "=== caldera2.log tail ==="
tail -30 /tmp/caldera2.log
echo "=== ports ==="
ss -tln | grep -E '8888|8443' || echo NOT-LISTENING
echo DONE
