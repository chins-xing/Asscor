#!/usr/bin/env python3
import json
for mode in ['C1','C2','C3']:
    print(f'=== CR-{mode} ===')
    for line in open(f'/tmp/exp-results/CR-{mode}.jsonl'):
        r = json.loads(line)
        print(f"  r{r['round']}: deployed={r.get('deployed_ports')} hits={len(r.get('decoy_hits') or [])} "
              f"mode={r.get('mode')} evidence_src={[e['SourceType'] for e in r['evidence']]}")
