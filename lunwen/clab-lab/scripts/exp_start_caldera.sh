#!/bin/bash
set -e
# Trim plugins list to only the ones we cloned (sandcat, stockpile, atomic)
cd /opt/caldera
sudo sed -i '/^plugins:/,/^port:/{/^- /d}' conf/default.yml
# Insert the three plugins after "plugins:"
sudo sed -i 's/^plugins:$/plugins:\n- sandcat\n- stockpile\n- atomic/' conf/default.yml
echo "=== plugins config now ==="
sed -n '/^plugins:/,/^port:/p' conf/default.yml
echo "=== starting caldera ==="
cd /opt/caldera
sudo nohup /opt/caldera/venv/bin/python server.py --fresh > /tmp/caldera.log 2>&1 &
echo "caldera PID: $!"
sleep 15
echo "=== caldera log tail ==="
tail -20 /tmp/caldera.log
echo "=== port check ==="
ss -tln | grep -E '8888|8443' || echo "NOT LISTENING"
echo DONE
