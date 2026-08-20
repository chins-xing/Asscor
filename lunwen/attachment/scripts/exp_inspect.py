#!/usr/bin/env python3
import json
for line in open('/tmp/exp-results/E2-C1.jsonl'):
    r = json.loads(line)
    print('round', r['round'], 'mode', r['mode'],
          'deployed', r.get('deployed_ports'), 'hits', r.get('decoy_hits'))
print('---E2-C2---')
for line in open('/tmp/exp-results/E2-C2.jsonl'):
    r = json.loads(line)
    print('round', r['round'], 'mode', r['mode'],
          'deployed', r.get('deployed_ports'), 'hits', r.get('decoy_hits'))
