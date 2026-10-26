#!/usr/bin/env python3
"""Revalidate all eight continuous profiles; never promote a short pilot to 24h."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from verify_soak import need, validate_report, validate_events, validate_engine_logs


def collect(root, pilot):
    seen = set()
    binaries, revisions, settings, runners = set(), set(), set(), set()
    rows = []
    for path in sorted(root.rglob('summary.json')):
        if path.name == 'suite-summary.json':
            continue
        summary = json.loads(path.read_text())
        if 'pilot' not in summary or 'binary_sha256' not in summary:
            continue
        need(summary['pilot'] == pilot, 'mixed pilot and formal evidence')
        need(summary['status'] == ('pilot_passed' if pilot else 'candidate_passed'), 'failed profile summary')
        need(summary.get('exit_code') == 0 and not summary.get('error'), 'nonzero or errored profile summary')
        need(not summary['cleanup'].get('interrupted_or_timeout', False), 'interrupted profile summary')
        need(summary['cleanup']['reaped'] and not summary['cleanup']['forced_kill'], 'process cleanup not complete')
        need(set(summary['files']) >= {'native/report.json', 'native/exchanges.jsonl.gz', 'native/engine.log.gz', 'stderr.log', 'stdout.log'}, 'missing evidence inventory')
        runners.add(summary['runner_sha256'])
        for name, sha in summary['files'].items():
            f = (path.parent / name).resolve()
            need(f.is_relative_to(path.parent.resolve()), 'unsafe evidence path')
            need(hashlib.sha256(f.read_bytes()).hexdigest() == sha, 'evidence changed: ' + name)
        native = path.parent / 'native'
        r = json.loads((native / 'report.json').read_text())
        measured = validate_report(r, pilot)
        events = validate_events(native / 'exchanges.jsonl.gz', r)
        validate_engine_logs(native, path.parent / 'stderr.log', r['settings']['pool_max'], r['transport'])
        key = (r['transport'], r['mode'])
        need(key not in seen, 'duplicate profile')
        seen.add(key)
        binaries.add(summary['binary_sha256'])
        match = re.search(r'vcs.revision=([0-9a-f]+)', r['build_info'])
        revisions.add(match.group(1) if match else 'unversioned-pilot')
        settings.add(tuple(r['settings'][k] for k in ('pool_min', 'pool_max', 'workers', 'qps', 'duration_seconds', 'warmup_seconds', 'sample_interval_seconds')))
        need(summary['qualifies_24h'] == measured['qualifies_24h'], 'qualification differs from raw duration/source')
        rows.append(dict(transport=key[0], mode=key[1], **measured, audited_events=events, report_sha256=hashlib.sha256((native / 'report.json').read_bytes()).hexdigest()))
    need(seen == {(t, m) for t in range(4) for m in (1, 2)}, 'all eight transport/flow profiles required')
    need(len(binaries) == len(revisions) == len(settings) == len(runners) == 1, 'profiles must share exact binary/source and workload')
    return {'status': 'pilot_passed' if pilot else 'candidate_passed', 'qualifies_24h': not pilot,
            'release_policy_automatically_updated': False, 'binary_sha256': list(binaries)[0], 'source': list(revisions)[0], 'profiles': rows}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--pilot', action='store_true')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        result = collect(a.artifacts, a.pilot)
    except (ValueError, KeyError, OSError, TypeError, EOFError) as exc:
        result = {'status': 'failed', 'qualifies_24h': False, 'error': f'{type(exc).__name__}: {exc}'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['status'] != 'failed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
