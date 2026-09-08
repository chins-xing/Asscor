#!/bin/bash
export http_proxy=http://172.31.0.1:58187
export https_proxy=http://172.31.0.1:58187
sudo git config --global http.proxy http://172.31.0.1:58187
sudo git config --global https.proxy http://172.31.0.1:58187
cd /opt/caldera/plugins || exit 1
for p in sandcat stockpile atomic; do
  echo "=== cloning $p ==="
  sudo git clone -q --depth 1 "https://github.com/mitre/$p.git" 2>&1 | tail -2
done
echo "=== verify ==="
ls -d sandcat stockpile atomic 2>&1
echo "--- stockpile abilities ---"
ls stockpile/data/abilities/ 2>&1 | head -6
echo "--- stockpile adversaries ---"
ls stockpile/data/adversaries/ 2>&1 | head -12
echo DONE
