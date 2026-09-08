#!/usr/bin/env python3
"""Full comparison analysis: intel (hits) vs cost (deployed ports)."""
import json

def load(p):
    return [json.loads(l) for l in open(p)]

print('=== CR comparison (3-round credential campaign, host9) ===')
print('mode | r | intent | S | strategy | deployed | hits')
summary = {}
for mode in ['C1', 'C2', 'C3']:
    rows = load(f'/tmp/exp-results/CR-{mode}.jsonl')
    th = sum(len(r.get('decoy_hits') or []) for r in rows)
    tp = sum(len(r.get('deployed_ports') or []) for r in rows)
    acc = sum(1 for r in rows if r['ground_truth'] and r['intent'] == r['ground_truth'])
    summary[mode] = (th, tp, acc, len(rows))
    for r in rows:
        print(f"  {mode} | r{r['round']} | {r['intent']:<10} | {r['sharpness']:.3f} | "
              f"{r['strategy']:<8} | {len(r.get('deployed_ports') or []):2d} | "
              f"{len(r.get('decoy_hits') or [])}")
print()
print('mode | total_hits | total_deployed | intent_acc | hits/port')
for mode in ['C1','C2','C3']:
    th, tp, acc, n = summary[mode]
    print(f"  {mode} | {th:10d} | {tp:14d} | {acc/n:6.0%} | {th/max(tp,1):.2f}")
print()
print('Interpretation:')
print('  C1 (no-ACL): 0 decoy hits -> attacker completely invisible to the loop')
print('  C2 (static): full decoy set every round -> visible, but fixed cost')
print('  C3 (ACL):    decoys follow prediction -> visible with prediction-driven cost')
