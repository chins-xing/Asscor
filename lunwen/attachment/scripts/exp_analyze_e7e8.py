#!/usr/bin/env python3
"""E7 convergence analysis + E8 ablation (next-TTP vs distribution)."""
import json, math, sys

def entropy(p):
    return -sum(v * math.log(v) for v in p.values() if v > 0)

def summarize_e7(path='/tmp/exp-results/E7.jsonl'):
    rows = []
    for line in open(path):
        r = json.loads(line)
        rows.append(r)
    print(f'=== E7: convergence over {len(rows)} identical credential rounds ===')
    print('round | intent | sharpness | cred_p | entropy | strategy')
    sharpness = [r['sharpness'] for r in rows]
    cred_p = [r['distribution'].get('credential', 0) for r in rows]
    entropies = [entropy(r['distribution']) for r in rows]
    for i, r in enumerate(rows):
        print(f"  {i+1:2d}   | {r['intent']:<9} | {r['sharpness']:.3f} | "
              f"{r['distribution'].get('credential',0):.3f} | {entropies[i]:.3f} | {r['strategy']}")
    # convergence metrics
    first_half = rows[:len(rows)//2]
    second_half = rows[len(rows)//2:]
    def mean(xs): return sum(xs)/len(xs)
    print(f'  sharpness: round1={sharpness[0]:.3f} -> round10={sharpness[-1]:.3f} '
          f'(first-half mean {mean(sharpness[:5]):.3f}, second-half mean {mean(sharpness[5:]):.3f})')
    print(f'  credential p: round1={cred_p[0]:.3f} -> round10={cred_p[-1]:.3f}')
    print(f'  entropy: round1={entropies[0]:.3f} -> round10={entropies[-1]:.3f} '
          f'(decrease = convergence toward a sharp distribution)')
    # sequence distance: KL between consecutive distributions
    kls = []
    for i in range(1, len(rows)):
        p = rows[i-1]['distribution']; q = rows[i]['distribution']
        kl = sum(p.get(k,0)*math.log((p.get(k,0)+1e-9)/(q.get(k,0)+1e-9)) for k in p)
        kls.append(kl)
    print(f'  KL(round_t || round_t+1): mean={mean(kls):.4f}, max={max(kls):.4f} '
          f'(low = stable/converged behavior)')
    return rows

def summarize_e8():
    """Ablation: next-TTP (deterministic argmax) vs action-distribution prediction
    on E2 credential data. A deterministic next-TTP picks one action; the
    distribution keeps the full ranking. Correctness: does the top action match
    ground truth? Coverage: does the true action appear in top-k?"""
    print('=== E8: ablation next-TTP vs distribution (on E2 data) ===')
    rows = []
    for line in open('/tmp/exp-results/E2.jsonl'):
        r = json.loads(line)
        d = r['distribution']
        ranked = sorted(d, key=d.get, reverse=True)
        rows.append((r['ground_truth'], d, ranked))
    next_ttp_correct = 0
    dist_top1_correct = 0
    dist_top2_correct = 0
    for gt, d, ranked in rows:
        if ranked[0] == gt: next_ttp_correct += 1
        if ranked[0] == gt: dist_top1_correct += 1
        if gt in ranked[:2]: dist_top2_correct += 1
    n = len(rows)
    print(f'  rounds: {n}')
    print(f'  next-TTP (argmax) top-1 accuracy: {next_ttp_correct}/{n} = {next_ttp_correct/n:.0%}')
    print(f'  distribution top-1 accuracy:      {dist_top1_correct}/{n} = {dist_top1_correct/n:.0%}')
    print(f'  distribution top-2 coverage:      {dist_top2_correct}/{n} = {dist_top2_correct/n:.0%}')
    print('  (distribution adds calibrated probabilities + ranked alternatives;')
    print('   next-TTP is a special case = its top-1)')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'e8':
        summarize_e8()
    else:
        summarize_e7()
