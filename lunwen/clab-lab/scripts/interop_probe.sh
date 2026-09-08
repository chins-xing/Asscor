#!/bin/bash
echo "=== binfmt_misc ==="
ls /proc/sys/fs/binfmt_misc/ 2>/dev/null
echo "=== wsl.conf ==="
cat /etc/wsl.conf 2>/dev/null || echo "(none)"
echo "=== cmd.exe interop ==="
cmd.exe /c "echo interop-ok" 2>&1 | head -2