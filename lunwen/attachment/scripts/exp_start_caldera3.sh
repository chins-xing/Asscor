#!/bin/bash
set -e
cd /opt/caldera
# Check which config is actually used
echo "=== local.yml plugins ==="
grep -A15 '^plugins:' conf/local.yml 2>/dev/null | head -16 || echo "no local.yml"
# Rewrite local.yml plugins to only our three
sudo tee conf/local.yml > /dev/null <<'EOF'
plugins:
- sandcat
- stockpile
- atomic
EOF
echo "=== local.yml written ==="
cat conf/local.yml
# Kill old, start fresh
sudo pkill -f 'server.py' 2>/dev/null
sleep 2
sudo setsid /opt/caldera/venv/bin/python server.py --fresh > /tmp/caldera3.log 2>&1 < /dev/null &
disown
echo "started, waiting 25s..."
sleep 25
echo "=== caldera3.log tail ==="
tail -25 /tmp/caldera3.log
echo "=== ports ==="
ss -tln | grep -E '8888|8443' || echo NOT-LISTENING
echo DONE
