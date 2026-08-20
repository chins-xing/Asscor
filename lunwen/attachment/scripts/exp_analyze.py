#!/usr/bin/env python3
"""Summarize experiment JSONL results (E1-E8)."""
import json, glob, sys

def summarize(path):
    rows = []
    for line in open(path):
        r = json.loads(line)
        top = max(r['distribution'], key=r['distribution'].get)
        hits = r.get('decoy_hits') or []
        rows.append({
            'round': r['round'], 'intent': r['intent'],
            'S': r['sharpness'], 'strategy': r['strategy'],
            'gt': r['ground_truth'], 'hits': len(hits),
            'top': top, 'top_p': r['distribution'][top],
            'latency_ms': r.get('latency_ms', 0),
        })
    return rows

if __name__ == '__main__':
    exps = sys.argv[1:] or ['E1','E2','E3','E4','E5','E6','E7','E8']
    for exp in exps:
        path = f'/tmp/exp-results/{exp}.jsonl'
        try:
            rows = summarize(path)
        except FileNotFoundError:
            print(f'=== {exp}: NOT FOUND ===')
            continue
        print(f'=== {exp}: {len(rows)} rounds ===')
        correct = 0
        total_lat = 0
        for r in rows:
            ok = (r['intent'] == r['gt']) if r['gt'] else (r['strategy'] == 'contain')
            if ok: correct += 1
            total_lat += r['latency_ms']
            print(f"  r{r['round']}: intent={r['intent']:<12} S={r['S']:.3f} "
                  f"strategy={r['strategy']:<8} gt={r['gt'] or 'N/A':<12} "
                  f"hits={r['hits']} top={r['top']}({r['top_p']:.3f}) "
                  f"lat={r['latency_ms']}ms")
        acc = correct / len(rows) if rows else 0
        print(f'  -> intent-tracking accuracy: {acc:.0%} | mean latency: {total_lat/len(rows):.0f}ms')
