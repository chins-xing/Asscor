#!/bin/bash
echo "=== all files under data/ (incl hidden) ==="
find /opt/caldera/data -type f 2>/dev/null | head -20
echo "=== backup contents (latest) ==="
tar tzf /opt/caldera/data/backup/backup-20260820000434.tar.gz 2>/dev/null | head -15
echo "=== grep token in all backups ==="
for b in /opt/caldera/data/backup/*.tar.gz; do
  echo "--- $b ---"
  tar xOzf "$b" 2>/dev/null | grep -aoP 'API_TOKEN.{0,50}' | head -2
done
echo DONE
