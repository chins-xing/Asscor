#!/usr/bin/env python3
import json
for exp in ['E1','E2','E3','E4','E5','E6','E7','E9']:
    rows = [json.loads(l) for l in open(f'/tmp/exp-results/{exp}.jsonl')]
    print(f'=== {exp}: {len(rows)} rounds ===')
    for r in rows:
        hits = len(r.get('decoy_hits') or [])
        dp = r.get('deployed_ports') or []
        print(f"  r{r['round']}: {r['intent']:<10} S={r['sharpness']:.3f} {r['strategy']:<8} "
              f"gt={r['ground_truth'] or 'N/A':<12} deployed={dp} hits={hits}")
