#!/bin/bash
set -e
cd /opt/caldera
# Backup the original local.yml if we clobbered it (regenerate from default)
sudo cp conf/default.yml conf/local.yml 2>/dev/null || true
# Now trim the plugins list in local.yml: remove all plugin lines, keep rest
sudo sed -i '/^plugins:/,/^[a-z_]*:/{/^- /d}' conf/local.yml
# Insert only our three plugins after "plugins:"
sudo sed -i 's/^plugins:$/plugins:\n- sandcat\n- stockpile\n- atomic/' conf/local.yml
echo "=== plugins section ==="
sed -n '/^plugins:/,/^[a-z_]*:/p' conf/local.yml | head -8
echo "=== crypt_salt present? ==="
grep -c 'crypt_salt' conf/local.yml
sudo pkill -f 'server.py' 2>/dev/null
sleep 2
sudo setsid /opt/caldera/venv/bin/python server.py --fresh > /tmp/caldera4.log 2>&1 < /dev/null &
disown
echo "started, waiting 25s..."
sleep 25
echo "=== caldera4.log tail ==="
tail -20 /tmp/caldera4.log
echo "=== ports ==="
ss -tln | grep -E '8888|8443' || echo NOT-LISTENING
echo DONE
