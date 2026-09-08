#!/usr/bin/env python3
import json
for exp in ['E1-C1', 'E1-C2', 'E1-C3']:
    print(f'=== {exp} ===')
    for line in open(f'/tmp/exp-results/{exp}.jsonl'):
        r = json.loads(line)
        print(f"  r{r['round']}: mode={r.get('mode')} deployed={r.get('deployed_ports')} "
              f"hits={len(r.get('decoy_hits') or [])} intent={r['intent']} S={r['sharpness']:.3f}")
