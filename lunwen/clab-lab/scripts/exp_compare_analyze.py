#!/usr/bin/env python3
"""Analyze comparison groups C1/C2/C3: hits (intel), deployed ports (cost),
intent accuracy."""
import json, sys

def load(path):
    rows = []
    for line in open(path):
        rows.append(json.loads(line))
    return rows

def report(exp, modes):
    print(f'=== {exp}: comparison C1(no-ACL) / C2(static) / C3(ACL dynamic) ===')
    print('mode | round | intent | S | strategy | deployed_ports | hits | gt')
    for mode in modes:
        rows = load(f'/tmp/exp-results/{exp}-{mode}.jsonl')
        total_hits = 0
        total_ports = 0
        correct = 0
        for r in rows:
            hits = len(r.get('decoy_hits') or [])
            ports = len(r.get('deployed_ports') or [])
            total_hits += hits
            total_ports += ports
            if r['ground_truth'] and r['intent'] == r['ground_truth']:
                correct += 1
            print(f"  {mode} | r{r['round']} | {r['intent']:<10} | {r['sharpness']:.3f} | "
                  f"{r['strategy']:<8} | {ports:2d} | {hits} | {r['ground_truth']}")
        acc = correct/len(rows) if rows else 0
        print(f"  -> {mode}: total_hits={total_hits} total_deployed={total_ports} "
              f"intent_acc={acc:.0%} hits/port={total_hits/max(total_ports,1):.2f}")
    print()

if __name__ == '__main__':
    report('E1', ['C1','C2','C3'])
    report('E2', ['C1','C2','C3'])
