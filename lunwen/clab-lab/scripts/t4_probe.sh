#!/bin/bash
echo "=== WSL 全部接口 (含 down) ==="
ip -br link
echo "=== WSL 网络模式 (.wslconfig) ==="
cat /mnt/c/Users/*/\.wslconfig 2>/dev/null || echo "(no .wslconfig)"
echo "=== Windows 宿主网卡 ==="
POWERSHELL="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
$POWERSHELL -NoProfile -Command "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed | Format-Table -AutoSize" 2>/dev/null || echo "(cannot query windows)"