#!/usr/bin/env python3
"""Reparse embedded procfs evidence; report deltas without changing acceptance."""
import argparse
import hashlib
import json
from pathlib import Path

REQUIRED = {'Rss', 'Pss', 'Anonymous', 'Private_Dirty', 'Private_Clean',
            'Shared_Dirty', 'Shared_Clean', 'Swap'}


def parse_rollup(raw):
    lines = raw.strip().splitlines()
    if len(lines) < 2 or not lines[0].rstrip().endswith('[rollup]'):
        raise ValueError('missing rollup header')
    result = {}
    for line in lines[1:]:
        f = line.split()
        if len(f) != 3 or not f[0].endswith(':') or f[2] != 'kB':
            raise ValueError('invalid rollup line')
        key = f[0][:-1]
        if key in result or not f[1].isascii() or not f[1].isdecimal():
            raise ValueError('duplicate or nonnumeric rollup field')
        value = int(f[1])
        if value > (2**64-1)//1024:
            raise ValueError('rollup overflow')
        result[key] = value*1024
    if not REQUIRED <= result.keys():
        raise ValueError('incomplete rollup')
    return result


def audit(path):
    r = json.loads(path.read_text())
    samples = [r['idle_baseline'], r['after_stop']] + [p['resources'] for p in r['points']]
    for s in samples:
        os_memory = s['os_memory']
        if os_memory.get('error') or parse_rollup(os_memory['smaps_rollup_raw']) != os_memory['bytes']:
            raise ValueError('missing, failed, or inconsistent OS evidence')
        if not 0 < os_memory['read_seconds'] < 60:
            raise ValueError('invalid read timing')
    warm = [p for p in r['points'] if p['phase'] == 'warmup'
            and p['at_seconds'] >= r['settings']['warmup_seconds']/2]
    steady = [p for p in r['points'] if p['phase'] == 'measured']
    baseline = max(warm, key=lambda p: p['resources']['rss'])
    peak = max(steady, key=lambda p: p['resources']['rss'])
    b, p = baseline['resources'], peak['resources']
    common = b['os_memory']['bytes'].keys() & p['os_memory']['bytes'].keys()
    return dict(report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                probe_status=r['status'], build_info=r['build_info'],
                sample_count=len(samples), baseline_at_seconds=baseline['at_seconds'],
                peak_at_seconds=peak['at_seconds'], statm_rss_delta=p['rss']-b['rss'],
                heap_alloc_delta=p['heap_alloc']-b['heap_alloc'],
                rollup_delta_bytes={k:p['os_memory']['bytes'][k]-b['os_memory']['bytes'][k]
                                    for k in sorted(common)},
                max_read_seconds=max(s['os_memory']['read_seconds'] for s in samples),
                scheduler_timing=r['scheduler_timing'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('reports', nargs='+', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = {str(path):audit(path) for path in a.reports}
    a.output.write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
