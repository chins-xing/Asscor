#!/bin/bash
# Extend asscor.clab.yml from 18 nodes (12 hosts) to 24 nodes (18 hosts).
# New hosts 13-18 hang off r2-r5 via new interfaces eth7/eth8.
set -e
cd ~/clab/asscor
cp asscor.clab.yml asscor.clab.yml.bak-18node

# 1. Add eth7/eth8 IPs to r2-r5 exec blocks (before the frr start line)
#    r2: 10.10.13.1/24 (eth7), 10.10.14.1/24 (eth8)
#    r3: 10.10.15.1/24 (eth7), 10.10.16.1/24 (eth8)
#    r4: 10.10.17.1/24 (eth7), 10.10.18.1/24 (eth8)
#    r5: (spare eth7/eth8 for future)
python3 - <<'PYEOF'
import re
p = 'asscor.clab.yml'
s = open(p).read()

# add eth7/eth8 ip addrs into router exec blocks
routers = {
  'r2': ['10.10.13.1/24 dev eth7', '10.10.14.1/24 dev eth8'],
  'r3': ['10.10.15.1/24 dev eth7', '10.10.16.1/24 dev eth8'],
  'r4': ['10.10.17.1/24 dev eth7', '10.10.18.1/24 dev eth8'],
}
for r, ips in routers.items():
    # insert ip addr add lines into the first bash -c of that router
    block = re.search(r'(' + r + r':\s*\n)(.*?)(?=\n    [a-z])', s, re.S).group(0)
    add_cmds = '; '.join('ip addr add %s 2>/dev/null' % ip for ip in ips)
    # append to the existing ip addr add chain: find the line ending with || true"
    new_block = block.replace(
        'ip route del default 2>/dev/null',
        add_cmds + '; ip route del default 2>/dev/null',
        1
    )
    s = s.replace(block, new_block)

# 2. add host13-18 definitions
hosts = {
  'host13': ('172.20.20.33', '10.10.13.10/24', '10.10.13.1'),
  'host14': ('172.20.20.34', '10.10.14.10/24', '10.10.14.1'),
  'host15': ('172.20.20.35', '10.10.15.10/24', '10.10.15.1'),
  'host16': ('172.20.20.36', '10.10.16.10/24', '10.10.16.1'),
  'host17': ('172.20.20.37', '10.10.17.10/24', '10.10.17.1'),
  'host18': ('172.20.20.38', '10.10.18.10/24', '10.10.18.1'),
}
host_lines = '\n'.join(
    '    %s: {kind: linux, mgmt-ipv4: %s, exec: ["bash -c \\"ip addr add %s dev eth1 2>/dev/null; ip route replace default via %s dev eth1 2>/dev/null || true\\""]}'
    % (h, mgmt, ip, gw) for h, (mgmt, ip, gw) in hosts.items()
)
s = s.replace('    host12:', host_lines + '\n    host12:')

# 3. add links
links = [
  'r2:eth7', 'host13:eth1',
  'r2:eth8', 'host14:eth1',
  'r3:eth7', 'host15:eth1',
  'r3:eth8', 'host16:eth1',
  'r4:eth7', 'host17:eth1',
  'r4:eth8', 'host18:eth1',
]
link_lines = '\n'.join(
    '    - endpoints: ["%s", "%s"]' % (links[i], links[i+1]) for i in range(0, len(links), 2)
)
s = s.replace('    - endpoints: ["r5:eth6", "host12:eth1"]',
              '    - endpoints: ["r5:eth6", "host12:eth1"]\n' + link_lines)

# update header comment
s = s.replace('18 节点 / 汇聚层环形冗余 / 12 主机', '24 节点 / 汇聚层环形冗余 / 18 主机')
s = s.replace('h9 h10 h11 h12   (host9-12 低风险基线)', 'h9 h10 h11 h12   (host9-12 低风险基线)  h13-h18 (扩展)')
open(p, 'w').write(s)
print('topology extended')
PYEOF

echo "=== verify new nodes ==="
grep -c 'host1[3-8]:' asscor.clab.yml
grep -c 'eth7\|eth8' asscor.clab.yml
echo "=== node count check ==="
grep -oE '^    (edge0|r[0-9]|host[0-9]+):' asscor.clab.yml | wc -l
echo DONE
