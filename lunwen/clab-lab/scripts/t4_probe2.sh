#!/bin/bash
PS="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
echo "=== 尝试 Get-NetAdapter ==="
$PS -NoProfile -ExecutionPolicy Bypass -Command "Get-NetAdapter | Format-Table -AutoSize" 2>&1 | head -20
echo "=== 尝试 CIM 查询 ==="
$PS -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_NetworkAdapter | Where-Object {\$_.PhysicalAdapter} | Select-Object Name, Manufacturer, Speed, NetConnectionStatus, MACAddress | Format-Table -AutoSize" 2>&1 | head -25