#!/bin/bash
echo "=== 代理环境变量 ==="
env | grep -iE "proxy" || echo "(no proxy env)"
echo "=== apt 代理 ==="
grep -riE "proxy" /etc/apt/apt.conf.d/ 2>/dev/null | head -5 || echo "(no apt proxy)"
echo "=== npm 配置 ==="
npm config get proxy 2>/dev/null; npm config get https-proxy 2>/dev/null; npm config get registry 2>/dev/null
echo "=== 路由 ==="
ip route | head -5