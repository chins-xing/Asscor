#!/bin/bash
echo "=== sudo 可用性 ==="
sudo -n true 2>/dev/null && echo "sudo NOPASSWD OK" || echo "sudo needs password"
echo "=== docker 状态 ==="
systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null | head -3