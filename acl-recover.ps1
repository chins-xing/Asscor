param()
$ErrorActionPreference = 'Stop'
$md = 'F:\Argus\docs\ASSCOR-Research-Core\paper\attacker-cognitive-loop.md'
$t = [System.IO.File]::ReadAllText($md, [System.Text.Encoding]::UTF8)
$gbk = [System.Text.Encoding]::GetEncoding(936)
$recoveredBytes = $gbk.GetBytes($t)
$recovered = [System.Text.Encoding]::UTF8.GetString($recoveredBytes)
$tmp = Join-Path $env:TEMP 'acl-md-recovered.txt'
[System.IO.File]::WriteAllText($tmp, $recovered, [System.Text.Encoding]::UTF8)
$lines = $recovered -split "`n"
$fffdLines = @()
for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i].Contains([char]0xFFFD)) { $fffdLines += $i+1 } }
$out = @()
$out += "recovered written: $tmp"
$out += "total lines: $($lines.Count), lines with U+FFFD: $($fffdLines.Count)"
foreach ($n in $fffdLines) {
  $ctx = $lines[$n-1].Trim()
  if ($ctx.Length -gt 90) { $ctx = $ctx.Substring(0,90) }
  $out += ("L{0}: {1}" -f $n, $ctx)
}
[System.IO.File]::WriteAllLines((Join-Path $env:TEMP 'acl-damage-report.txt'), $out, [System.Text.Encoding]::UTF8)
Write-Output 'done'
