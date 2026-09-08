#!/bin/bash
echo "=== 外网连通性 ==="
timeout 12 curl -sI https://registry-1.docker.io/v2/ -o /dev/null -w "docker hub: HTTP %{http_code} (%{time_total}s)\n" 2>&1 || echo "docker hub: FAIL"
timeout 12 curl -sI https://github.com -o /dev/null -w "github: HTTP %{http_code} (%{time_total}s)\n" 2>&1 || echo "github: FAIL"
timeout 12 curl -sI https://registry.npmjs.org -o /dev/null -w "npm: HTTP %{http_code} (%{time_total}s)\n" 2>&1 || echo "npm: FAIL"
timeout 10 getent hosts registry-1.docker.io >/dev/null && echo "dns: OK" || echo "dns: FAIL"