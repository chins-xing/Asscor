#!/bin/bash
set -e
echo "=== 1. 导出 CA ==="
mkdir -p /tmp/asscor-ca
docker cp asc-asscor-edge0:/etc/asscor/certs/ca.crt /tmp/asscor-ca/ca.crt
docker cp asc-asscor-edge0:/etc/asscor/certs/ca.key /tmp/asscor-ca/ca.key
chmod 600 /tmp/asscor-ca/ca.key
echo "=== 2. 签发 host1-4 证书 ==="
cd /tmp/asscor-ca
for i in 1 2 3 4; do
  openssl req -new -newkey rsa:2048 -nodes -keyout host$i.key -out host$i.csr -subj "/CN=host$i" 2>/dev/null
  printf "extendedKeyUsage = clientAuth\n" > ext$i.cnf
  openssl x509 -req -in host$i.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out host$i.crt -days 365 -extfile ext$i.cnf 2>/dev/null
  echo "host$i: $(openssl x509 -in host$i.crt -noout -subject -fingerprint -sha256 | tr '\n' ' ')"
done