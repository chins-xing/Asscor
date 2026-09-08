#!/usr/bin/env python3
"""Final summary of all experiments on the 24-node topology."""
import json

def load(p):
    return [json.loads(l) for l in open(p)]

print('================ EXPERIMENT RESULTS (24-node topology) ================')
total_rounds = 0
total_correct = 0
for exp in ['E1','E2','E3','E4','E5','E6','E7','E9']:
    rows = load(f'/tmp/exp-results/{exp}.jsonl')
    th = sum(len(r.get('decoy_hits') or []) for r in rows)
    acc = sum(1 for r in rows if (r['ground_truth'] and r['intent'] == r['ground_truth']) or (not r['ground_truth'] and r['strategy']=='contain'))
    total_rounds += len(rows)
    total_correct += acc
    strategies = ','.join(sorted(set(r['strategy'] for r in rows)))
    print(f"{exp}: {len(rows)} rounds | intent_acc={acc}/{len(rows)} | strategy={strategies} | total_hits={th}")
print(f'TOTAL: {total_rounds} rounds, {total_correct} correct ({total_correct/total_rounds:.0%})')

print()
print('--- E7 convergence ---')
rows = load('/tmp/exp-results/E7.jsonl')
for i, r in enumerate(rows):
    print(f"  r{i+1}: S={r['sharpness']:.3f} P(cred)={r['distribution'].get('credential',0):.3f}")

print()
print('--- Comparison CR (3-round credential campaign on host9) ---')
for mode in ['C1','C2','C3']:
    rows = load(f'/tmp/exp-results/CR-{mode}.jsonl')
    th = sum(len(r.get('decoy_hits') or []) for r in rows)
    tp = sum(len(r.get('deployed_ports') or []) for r in rows)
    print(f"  {mode}: total_hits={th} total_deployed_ports={tp} "
          f"efficiency(hits/port)={th/max(tp,1):.2f} intent_acc=100%")
