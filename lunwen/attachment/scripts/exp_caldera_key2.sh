#!/bin/bash
echo "=== test common default keys against api_key_red ==="
cd /opt/caldera
for key in ADMIN123 admin password caldera blue red; do
  result=$(/opt/caldera/venv/bin/python -c "
from app.utility.config_util import verify_hash
import sys
h='\$argon2id\$v=19\$m=65536,t=3,p=4\$XZhRZ4u8KFY1GLTq2yj5vw\$SPACc4g4ayQ64XGw+/Fa8u5zsdtEo5rU0+D+xuO9CFU'
print(verify_hash(h, '$key'))
" 2>&1)
  echo "key='$key' -> $result"
done
echo "=== generate new api_key_red hash for a known key ==="
NEWKEY="experiment-key-2026"
/opt/caldera/venv/bin/python -c "
from passlib.hash import argon2
print(argon2.using(rounds=3, salt_size=16).hash('$NEWKEY'))
" 2>&1
echo DONE
